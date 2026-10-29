package safeview

import (
	"strings"
	"testing"
)

const confirmation = "From: Letter <hi@letter.example>\r\n" +
	"To: m-abc@in.test\r\n" +
	"Subject: =?utf-8?q?Please_confirm?=\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/alternative; boundary=x\r\n\r\n" +
	"--x\r\n" +
	"Content-Type: text/html; charset=utf-8\r\n" +
	"Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
	"<html><head><style>p{color:red}</style></head><body><script>alert(1)</script>" +
	"<p>Press the button to confirm.</p><a href=3D\"https://letter.example/confirm?t=3D1\">Yes, subscribe me</a>" +
	"<a href=3D\"javascript:alert(1)\">bad</a><img src=3D\"https://track.example/p.gif\"></body></html>\r\n" +
	"--x--\r\n"

func TestParse(t *testing.T) {
	v, err := Parse([]byte(confirmation))
	if err != nil {
		t.Fatal(err)
	}
	if v.Subject != "Please confirm" || v.From != "Letter <hi@letter.example>" {
		t.Errorf("headers = %q %q", v.Subject, v.From)
	}
	if !strings.Contains(v.Text, "Press the button to confirm.") || strings.Contains(v.Text, "alert(1)") || strings.Contains(v.Text, "color:red") {
		t.Errorf("text = %q", v.Text)
	}
	if len(v.Links) != 2 {
		t.Fatalf("links = %+v", v.Links)
	}
	if l := v.Links[0]; l.URL != "https://letter.example/confirm?t=1" || l.Text != "Yes, subscribe me" || !l.Web {
		t.Errorf("confirm link = %+v", l)
	}
	if l := v.Links[1]; l.Web {
		t.Errorf("a javascript link is shown as a link: %+v", l)
	}
}

func TestParsePlainBase64(t *testing.T) {
	raw := "Subject: Hi\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		"Q29uZmlybSBhdCBodHRwczovL2V4YW1w\r\nbGUuY29tL2M/eD0xLg==\r\n"
	v, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if v.Text != "Confirm at https://example.com/c?x=1." || len(v.Links) != 1 || v.Links[0].URL != "https://example.com/c?x=1" {
		t.Errorf("view = %+v", v)
	}
}
