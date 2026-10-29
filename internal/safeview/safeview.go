// Package safeview turns a stored message into text and a list of links that
// can be shown without rendering its HTML, loading its images, or running
// anything in it. It is how a user finds a subscription confirmation link
// and opens it themselves; SendScore never follows one.
package safeview

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Limits on what is read and shown.
const (
	maxDepth = 8
	maxParts = 100
	maxText  = 200 << 10
	maxLinks = 200
)

// View is the readable form of a message.
type View struct {
	From, To, Subject, Date string
	Text                    string
	Links                   []Link
}

// Link is one link in the message.
type Link struct {
	URL  string
	Text string
	// Web is set for an http or https link, the only kind shown as a link.
	Web bool
}

// Parse reads a raw message.
func Parse(raw []byte) (View, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return View{}, err
	}
	dec := new(mime.WordDecoder)
	header := func(k string) string {
		v := msg.Header.Get(k)
		if d, err := dec.DecodeHeader(v); err == nil {
			return d
		}
		return v
	}
	v := View{From: header("From"), To: header("To"), Subject: header("Subject"), Date: msg.Header.Get("Date")}
	p := &parser{seen: map[string]bool{}}
	p.part(msg.Header, msg.Body, 0)
	text := p.plain
	if strings.TrimSpace(text) == "" {
		text = p.htmlText
	}
	if len(text) > maxText {
		text = text[:maxText]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
		text += "\n\n(The rest of the message is not shown.)"
	}
	v.Text = strings.ToValidUTF8(strings.TrimSpace(text), "�")
	// Links in the plain text count too, after those from the HTML.
	for _, u := range urlPattern.FindAllString(p.plain, -1) {
		p.addLink(strings.TrimRight(u, ".,;:!?)]'\""), "")
	}
	v.Links = p.links
	return v, nil
}

// header is a message's or a part's header.
type header interface{ Get(string) string }

type parser struct {
	plain, htmlText string
	links           []Link
	seen            map[string]bool
	parts           int
}

var urlPattern = regexp.MustCompile(`https?://[^\s<>"]+`)

func (p *parser) part(h header, body io.Reader, depth int) {
	p.parts++
	if depth > maxDepth || p.parts > maxParts {
		return
	}
	ctype, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		ctype = "text/plain"
	}
	if strings.HasPrefix(ctype, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			part, err := mr.NextRawPart()
			if err != nil {
				return
			}
			p.part(part.Header, part, depth+1)
		}
	}
	if strings.HasPrefix(strings.ToLower(h.Get("Content-Disposition")), "attachment") {
		return
	}
	switch ctype {
	case "text/plain":
		if p.plain == "" {
			p.plain = string(decode(h, body))
		}
	case "text/html":
		if p.htmlText == "" {
			p.htmlText = p.fromHTML(decode(h, body))
		}
	}
}

// decode undoes the transfer encoding, reading at most maxText*4 bytes.
func decode(h header, body io.Reader) []byte {
	r := io.LimitReader(body, maxText*4)
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, &stripSpace{r: bufio.NewReader(r)})
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	}
	b, _ := io.ReadAll(r)
	return b
}

// stripSpace drops the line breaks inside base64.
type stripSpace struct{ r io.ByteReader }

func (s *stripSpace) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c, err := s.r.ReadByte()
		if err != nil {
			return n, err
		}
		if c == '\r' || c == '\n' || c == ' ' || c == '\t' {
			continue
		}
		p[n] = c
		n++
	}
	return n, nil
}

// fromHTML returns the text of an HTML body and collects its links. Script,
// style, and head contents are dropped, and block elements end lines.
func (p *parser) fromHTML(b []byte) string {
	z := html.NewTokenizer(bytes.NewReader(b))
	var out strings.Builder
	skip := 0
	var href string
	var anchor strings.Builder
	for {
		switch z.Next() {
		case html.ErrorToken:
			return collapse(out.String())
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			switch tag {
			case "script", "style", "head", "title":
				skip++
			case "br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table":
				out.WriteString("\n")
			case "a":
				href = ""
				anchor.Reset()
				for hasAttr {
					var k, v []byte
					k, v, hasAttr = z.TagAttr()
					if string(k) == "href" {
						href = strings.TrimSpace(string(v))
					}
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "script", "style", "head", "title":
				if skip > 0 {
					skip--
				}
			case "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table":
				out.WriteString("\n")
			case "a":
				if href != "" {
					p.addLink(href, collapseLine(anchor.String()))
				}
				href = ""
			}
		case html.TextToken:
			if skip == 0 {
				t := string(z.Text())
				out.WriteString(t)
				if href != "" {
					anchor.WriteString(t)
				}
			}
		}
	}
}

func (p *parser) addLink(raw, text string) {
	if raw == "" || p.seen[raw] || len(p.links) >= maxLinks {
		return
	}
	p.seen[raw] = true
	u, err := url.Parse(raw)
	web := err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
	p.links = append(p.links, Link{URL: raw, Text: text, Web: web})
}

var spaces = regexp.MustCompile(`[ \t\x{00a0}]+`)
var blankLines = regexp.MustCompile(`\n\s*\n\s*\n+`)

func collapse(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(spaces.ReplaceAllString(l, " "))
	}
	return blankLines.ReplaceAllString(strings.Join(lines, "\n"), "\n\n")
}

func collapseLine(s string) string { return strings.Join(strings.Fields(s), " ") }
