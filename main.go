// Command sendscore-app runs the SendScore web app and its SMTP receiver in
// one process, sharing one SQLite database.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/sendscore/sendscore-app/internal/db"
	"github.com/sendscore/sendscore-app/internal/receiver"
	"github.com/sendscore/sendscore-app/internal/web"
)

func main() {
	loadDotEnv(".env.local")
	loadDotEnv(".env")
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	dbPath := getenv("SENDSCORE_DB", "sendscore.db")
	store, err := db.Open(dbPath)
	if err != nil {
		log.Error("database init failed", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	httpAddr := getenv("SENDSCORE_ADDR", "127.0.0.1:3014")
	smtpAddr := getenv("SENDSCORE_SMTP_ADDR", "127.0.0.1:2525")
	mailDomain := getenv("SENDSCORE_MAIL_DOMAIN", "localhost")
	baseURL := strings.TrimRight(getenv("SENDSCORE_BASE_URL", "http://"+httpAddr), "/")

	app, err := web.New(web.Config{
		BaseURL:    baseURL,
		MailDomain: mailDomain,
		AddressTTL: 24 * time.Hour,
		ReportTTL:  7 * 24 * time.Hour,
	}, store, log)
	if err != nil {
		log.Error("templates", "err", err)
		os.Exit(1)
	}
	rcv := receiver.New(receiver.Config{
		Addr:       smtpAddr,
		MailDomain: mailDomain,
		ReportTTL:  7 * 24 * time.Hour,
	}, store, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              httpAddr,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		log.Info("web listening", "addr", httpAddr, "base_url", baseURL, "db", dbPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("web server failed", "err", err)
			os.Exit(1)
		}
	}()
	go func() {
		log.Info("smtp listening", "addr", smtpAddr, "mail_domain", mailDomain)
		if err := rcv.ListenAndServe(); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			log.Error("smtp server failed", "err", err)
			os.Exit(1)
		}
	}()
	go sweep(ctx, store, log)

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	_ = rcv.Close()
}

// sweep deletes expired reports every hour.
func sweep(ctx context.Context, store *db.Store, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := store.Sweep(ctx); err != nil {
			log.Error("sweep", "err", err)
		} else if n > 0 {
			log.Info("swept expired reports", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// loadDotEnv fills variables that are not already set from a KEY=value file.
func loadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
}
