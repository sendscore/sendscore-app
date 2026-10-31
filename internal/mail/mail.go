// Package mail sends the app's own email (sign-in links and alerts) through
// the Amazon SES API. Without SES credentials it logs the message instead,
// so sign-in works in development with the link printed to stdout.
package mail

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// Sender sends a plain-text email.
type Sender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// Alert is an alert email, with a plain text and an HTML body.
type Alert struct {
	To, Subject, Text, HTML string
}

// Alerter sends alert emails, from the alerts address.
type Alerter interface {
	SendAlert(ctx context.Context, a Alert) error
}

// sendTimeout bounds one SES call, which runs inside a sign-in request.
const sendTimeout = 10 * time.Second

// SES sends through the Amazon SES API (SESv2).
type SES struct {
	client    *sesv2.Client
	from      string
	alertFrom string
}

// Log writes the message to the log instead of sending it. Logged bodies
// hold working sign-in links, so it is for development only.
type Log struct{ Logger *slog.Logger }

// Send implements Sender.
func (l Log) Send(_ context.Context, to, subject, body string) error {
	l.Logger.Info("email not sent (SES is not configured)", "to", to, "subject", subject, "body", body)
	return nil
}

// SendAlert implements Alerter.
func (l Log) SendAlert(_ context.Context, a Alert) error {
	l.Logger.Info("alert not sent (SES is not configured)", "to", a.To, "subject", a.Subject, "body", a.Text)
	return nil
}

// FromEnv returns an SES sender from SES_ACCESS_KEY_ID, SES_SECRET_ACCESS_KEY,
// SES_REGION (default us-east-1), SENDSCORE_MAIL_FROM, and
// SENDSCORE_ALERT_FROM, or ok false when the keys are not set. Both senders
// are required with the keys, since SES refuses any address it has not
// verified for this account, and that would stop every sign-in.
func FromEnv(ctx context.Context) (s *SES, ok bool, err error) {
	id, secret := os.Getenv("SES_ACCESS_KEY_ID"), os.Getenv("SES_SECRET_ACCESS_KEY")
	if id == "" || secret == "" {
		return nil, false, nil
	}
	from, alertFrom := os.Getenv("SENDSCORE_MAIL_FROM"), os.Getenv("SENDSCORE_ALERT_FROM")
	if from == "" || alertFrom == "" {
		return nil, false, errors.New("SENDSCORE_MAIL_FROM and SENDSCORE_ALERT_FROM are required with the SES keys: set both to addresses SES has verified")
	}
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(getenv("SES_REGION", "us-east-1")),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(id, secret, "")),
	)
	if err != nil {
		return nil, false, err
	}
	return &SES{client: sesv2.NewFromConfig(cfg), from: from, alertFrom: alertFrom}, true, nil
}

// AlertFrom is the sender of alerts.
func (s *SES) AlertFrom() string { return s.alertFrom }

// Permanent reports whether SES refused a send in a way trying again cannot
// fix, as opposed to an outage or throttling.
func Permanent(err error) bool {
	var rejected *types.MessageRejected
	var bad *types.BadRequestException
	var domain *types.MailFromDomainNotVerifiedException
	return errors.As(err, &rejected) || errors.As(err, &bad) || errors.As(err, &domain)
}

// From is the sender address.
func (s *SES) From() string { return s.from }

// SendAlert implements Alerter.
func (s *SES) SendAlert(ctx context.Context, a Alert) error {
	body := &types.Body{Text: content(a.Text), Html: content(a.HTML)}
	if err := s.send(ctx, s.alertFrom, a.To, a.Subject, body); err != nil {
		return fmt.Errorf("send alert: %w", err)
	}
	return nil
}

// Send implements Sender.
func (s *SES) Send(ctx context.Context, to, subject, body string) error {
	if err := s.send(ctx, s.from, to, subject, &types.Body{Text: content(body)}); err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	return nil
}

func content(s string) *types.Content {
	return &types.Content{Data: aws.String(s), Charset: aws.String("UTF-8")}
}

func (s *SES) send(ctx context.Context, from, to, subject string, body *types.Body) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	_, err := s.client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(from),
		Destination:      &types.Destination{ToAddresses: []string{to}},
		Content:          &types.EmailContent{Simple: &types.Message{Subject: content(subject), Body: body}},
	})
	return err
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
