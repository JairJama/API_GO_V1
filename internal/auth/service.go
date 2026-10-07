package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	users        UserStore
	sessions     SessionStore
	passwordCost int
	sessionTTL   time.Duration
}

type Config struct {
	PasswordCost int
	SessionTTL   time.Duration
}

func NewService(users UserStore, sessions SessionStore, cfg Config) *Service {
	if cfg.PasswordCost <= 0 {
		cfg.PasswordCost = bcrypt.DefaultCost
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	return &Service{users: users, sessions: sessions, passwordCost: cfg.PasswordCost, sessionTTL: cfg.SessionTTL}
}

func (s *Service) Register(ctx context.Context, email, password string) (User, error) {
	normalized, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	if err := validatePassword(password); err != nil {
		return User{}, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.passwordCost)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}
	return s.users.Create(ctx, email, normalized, string(hash))
}

func (s *Service) Login(ctx context.Context, email, password, userAgent, ipAddress string) (User, string, time.Time, error) {
	normalized, err := normalizeEmail(email)
	if err != nil {
		return User{}, "", time.Time{}, ErrInvalidCredentials
	}
	user, err := s.users.FindByEmail(ctx, normalized)
	if err != nil {
		return User{}, "", time.Time{}, ErrInvalidCredentials
	}
	if user.Status != "active" {
		return User{}, "", time.Time{}, ErrUserBlocked
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return User{}, "", time.Time{}, ErrInvalidCredentials
	}

	sessionID := uuid.New()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return User{}, "", time.Time{}, fmt.Errorf("generate session secret: %w", err)
	}
	hash := sha256.Sum256(secret)
	expiresAt := time.Now().UTC().Add(s.sessionTTL)
	session := Session{
		ID:             sessionID,
		UserID:         user.ID,
		TokenHash:      hash[:],
		ExpiresAt:      expiresAt,
		SessionVersion: user.SessionVersion,
		UserAgent:      userAgent,
		IPAddress:      ipAddress,
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return User{}, "", time.Time{}, fmt.Errorf("create session: %w", err)
	}
	if err := s.users.MarkLogin(ctx, user.ID); err != nil {
		return User{}, "", time.Time{}, fmt.Errorf("mark login: %w", err)
	}

	return user, formatSessionToken(sessionID, secret), expiresAt, nil
}

func (s *Service) Authenticate(ctx context.Context, rawToken string) (User, Session, error) {
	sessionID, secretHash, err := parseSessionToken(rawToken)
	if err != nil {
		return User{}, Session{}, ErrNotAuthenticated
	}
	session, err := s.sessions.FindByID(ctx, sessionID)
	if err != nil {
		return User{}, Session{}, ErrNotAuthenticated
	}
	if subtle.ConstantTimeCompare(secretHash, session.TokenHash) != 1 || session.RevokedAt != nil || !time.Now().UTC().Before(session.ExpiresAt) {
		return User{}, Session{}, ErrNotAuthenticated
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if err != nil || user.Status != "active" || user.SessionVersion != session.SessionVersion {
		return User{}, Session{}, ErrNotAuthenticated
	}
	return user, session, nil
}

func (s *Service) Logout(ctx context.Context, rawToken string) error {
	sessionID, _, err := parseSessionToken(rawToken)
	if err != nil {
		return nil
	}
	return s.sessions.Revoke(ctx, sessionID)
}

func normalizeEmail(email string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(email))
	parsed, err := mail.ParseAddress(normalized)
	if err != nil || parsed.Address != normalized || !strings.Contains(normalized, "@") {
		return "", ErrInvalidInput
	}
	return normalized, nil
}

func validatePassword(password string) error {
	if len(password) < 8 || len(password) > 72 {
		return ErrInvalidInput
	}
	return nil
}

func formatSessionToken(id uuid.UUID, secret []byte) string {
	return "sid_" + id.String() + "_" + base64.RawURLEncoding.EncodeToString(secret)
}

func parseSessionToken(raw string) (uuid.UUID, []byte, error) {
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != "sid" {
		return uuid.Nil, nil, ErrNotAuthenticated
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, nil, ErrNotAuthenticated
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != 32 {
		return uuid.Nil, nil, ErrNotAuthenticated
	}
	hash := sha256.Sum256(secret)
	return id, hash[:], nil
}
