// Package mail sends the app's own email (sign-in links and alerts) through
// the Amazon SES API. Without SES credentials it logs the message instead,
// so sign-in works in development with the link printed to stdout.
package mail

import (
	"context"
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
// SES_REGION (default us-east-1), SENDSCORE_MAIL_FROM (default
// "SendScore <hello@sendscore.ai>"), and SENDSCORE_ALERT_FROM (default
// "SendScore alerts <alerts@sendscore.ai>"), or ok false when the keys are
// not set.
func FromEnv(ctx context.Context) (s *SES, ok bool, err error) {
	id, secret := os.Getenv("SES_ACCESS_KEY_ID"), os.Getenv("SES_SECRET_ACCESS_KEY")
	if id == "" || secret == "" {
		return nil, false, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(getenv("SES_REGION", "us-east-1")),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(id, secret, "")),
	)
	if err != nil {
		return nil, false, err
	}
	return &SES{client: sesv2.NewFromConfig(cfg), from: getenv("SENDSCORE_MAIL_FROM", "SendScore <hello@sendscore.ai>"),
		alertFrom: AlertFrom()}, true, nil
}

// AlertFrom is the sender of alerts.
func AlertFrom() string {
	return getenv("SENDSCORE_ALERT_FROM", "SendScore alerts <alerts@sendscore.ai>")
}

// From is the sender address.
func (s *SES) From() string { return s.from }

// SendAlert implements Alerter.
func (s *SES) SendAlert(ctx context.Context, a Alert) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	_, err := s.client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(s.alertFrom),
		Destination:      &types.Destination{ToAddresses: []string{a.To}},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{Data: aws.String(a.Subject), Charset: aws.String("UTF-8")},
				Body: &types.Body{
					Text: &types.Content{Data: aws.String(a.Text), Charset: aws.String("UTF-8")},
					Html: &types.Content{Data: aws.String(a.HTML), Charset: aws.String("UTF-8")},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("send alert: %w", err)
	}
	return nil
}

// Send implements Sender.
func (s *SES) Send(ctx context.Context, to, subject, body string) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	_, err := s.client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(s.from),
		Destination:      &types.Destination{ToAddresses: []string{to}},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{Data: aws.String(subject)},
				Body:    &types.Body{Text: &types.Content{Data: aws.String(body)}},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
