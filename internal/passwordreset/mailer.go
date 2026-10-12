package passwordreset

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

// LogMailer is exclusively for local development. It writes a reset URL to the
// configured development logger; production must use a real mailer instead.
type LogMailer struct {
	logger  *slog.Logger
	baseURL string
}

func NewLogMailer(logger *slog.Logger, baseURL string) *LogMailer {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogMailer{logger: logger, baseURL: baseURL}
}

func (m *LogMailer) Available() bool {
	if m == nil {
		return false
	}
	_, err := resetLink(m.baseURL, "placeholder")
	return err == nil
}

func (m *LogMailer) SendResetLink(_ context.Context, _ string, token string, expiresAt time.Time) error {
	if !m.Available() {
		return ErrMailerUnavailable
	}
	link, err := resetLink(m.baseURL, token)
	if err != nil {
		return err
	}
	m.logger.Info("development password reset link", "link", link, "expires_at", expiresAt.UTC())
	return nil
}

type unavailableMailer struct{}

func NewUnavailableMailer() PasswordResetMailer { return unavailableMailer{} }
func (unavailableMailer) Available() bool       { return false }
func (unavailableMailer) SendResetLink(context.Context, string, string, time.Time) error {
	return ErrMailerUnavailable
}

func resetLink(baseURL, token string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("invalid password reset URL base")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/reset-password"
	query := parsed.Query()
	query.Set("token", token)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
