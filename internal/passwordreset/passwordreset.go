// Package passwordreset contains the application flow for password recovery.
package passwordreset

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"example.com/go-security-api/internal/auth"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken      = errors.New("invalid password reset token")
	ErrMailerUnavailable = errors.New("password reset mailer unavailable")
)

// PasswordResetStore persists hashed reset tokens and atomically changes a password.
type PasswordResetStore interface {
	CreateToken(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) error
	ConsumeAndReset(ctx context.Context, tokenHash []byte, passwordHash string) (auth.User, error)
}

// PasswordResetMailer is intentionally small so an SMTP implementation can replace LogMailer.
type PasswordResetMailer interface {
	Available() bool
	SendResetLink(ctx context.Context, email, token string, expiresAt time.Time) error
}

type userFinder interface {
	FindByEmail(ctx context.Context, emailNormalized string) (auth.User, error)
}

type RequestResult struct {
	UserID      *uuid.UUID
	RateLimited bool
}

type Service struct {
	users        userFinder
	store        PasswordResetStore
	mailer       PasswordResetMailer
	limiter      *MemoryLimiter
	passwordCost int
	ttl          time.Duration
	now          func() time.Time
}

func NewService(users userFinder, store PasswordResetStore, mailer PasswordResetMailer, limiter *MemoryLimiter, passwordCost int, ttl time.Duration) *Service {
	if passwordCost <= 0 {
		passwordCost = bcrypt.DefaultCost
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	if limiter == nil {
		limiter = NewMemoryLimiter(3, 5, 15*time.Minute)
	}
	return &Service{users: users, store: store, mailer: mailer, limiter: limiter, passwordCost: passwordCost, ttl: ttl, now: func() time.Time { return time.Now().UTC() }}
}

// Request creates a one-time token only for active known users. Its caller must always
// return the same accepted response for a known and an unknown email address.
func (s *Service) Request(ctx context.Context, email, ip string) (RequestResult, error) {
	if s == nil || s.mailer == nil || !s.mailer.Available() {
		return RequestResult{}, ErrMailerUnavailable
	}

	normalized := strings.ToLower(strings.TrimSpace(email))
	if !s.limiter.Allow(ip, normalized, s.now()) {
		return RequestResult{RateLimited: true}, nil
	}

	normalized, err := auth.NormalizeEmail(email)
	if err != nil || s.users == nil || s.store == nil {
		return RequestResult{}, nil
	}
	user, err := s.users.FindByEmail(ctx, normalized)
	if errors.Is(err, auth.ErrUserNotFound) || user.Status != "active" {
		return RequestResult{}, nil
	}
	if err != nil {
		return RequestResult{}, fmt.Errorf("find reset user: %w", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return RequestResult{}, fmt.Errorf("generate reset token: %w", err)
	}
	token := fmt.Sprintf("prt_%x", secret)
	tokenHash := sha256.Sum256([]byte(token))
	expiresAt := s.now().Add(s.ttl)
	if err := s.store.CreateToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		return RequestResult{}, fmt.Errorf("store reset token: %w", err)
	}
	if err := s.mailer.SendResetLink(ctx, user.Email, token, expiresAt); err != nil {
		return RequestResult{}, fmt.Errorf("send reset link: %w", err)
	}
	userID := user.ID
	return RequestResult{UserID: &userID}, nil
}

// Reset validates the new password then consumes the matching token exactly once.
func (s *Service) Reset(ctx context.Context, token, password string) (auth.User, error) {
	if s == nil || s.store == nil || strings.TrimSpace(token) == "" || auth.ValidatePassword(password) != nil {
		return auth.User{}, ErrInvalidToken
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), s.passwordCost)
	if err != nil {
		return auth.User{}, fmt.Errorf("hash reset password: %w", err)
	}
	tokenHash := sha256.Sum256([]byte(token))
	user, err := s.store.ConsumeAndReset(ctx, tokenHash[:], string(passwordHash))
	if errors.Is(err, ErrInvalidToken) {
		return auth.User{}, ErrInvalidToken
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("consume reset token: %w", err)
	}
	return user, nil
}
