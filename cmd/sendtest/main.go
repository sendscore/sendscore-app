// Command sendtest delivers a saved .eml to the local SMTP receiver, for
// testing without a public MX record. The address may be a test address
// (t-...) or a newsletter's monitoring address (m-...).
//
//	go run ./cmd/sendtest -to t-abc123@localhost message.eml
package main

import (
	"flag"
	"fmt"
	"net/mail"
	"os"
	"strings"

	"github.com/emersion/go-smtp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:2525", "SMTP receiver address")
	to := flag.String("to", "", "test or monitoring address to deliver to (required)")
	from := flag.String("from", "", "envelope sender; defaults to the message's Return-Path or From")
	flag.Parse()
	if *to == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: sendtest -to t-<token>@localhost (or m-<token>@localhost) [-from sender] message.eml")
		os.Exit(64)
	}
	raw, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sender := *from
	if sender == "" {
		if m, err := mail.ReadMessage(strings.NewReader(string(raw))); err == nil {
			sender = strings.Trim(m.Header.Get("Return-Path"), "<> ")
			if sender == "" {
				if a, err := mail.ParseAddress(m.Header.Get("From")); err == nil {
					sender = a.Address
				}
			}
		}
	}
	if err := send(*addr, sender, *to, raw); err != nil {
		fmt.Fprintln(os.Stderr, "send failed:", err)
		os.Exit(1)
	}
	fmt.Println("delivered to", *to)
}

// send delivers without STARTTLS: the local receiver has no certificate,
// and the report will say the message arrived without TLS.
func send(addr, from, to string, raw []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("sendtest.localhost"); err != nil {
		return err
	}
	if err := c.Mail(from, nil); err != nil {
		return err
	}
	if err := c.Rcpt(to, nil); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
