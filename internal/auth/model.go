package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput       = errors.New("invalid input")
	ErrEmailExists        = errors.New("email already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserBlocked        = errors.New("user blocked")
	ErrNotAuthenticated   = errors.New("not authenticated")
)

type User struct {
	ID              uuid.UUID
	Email           string
	EmailNormalized string
	PasswordHash    string
	Role            string
	Status          string
	SessionVersion  int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastLoginAt     *time.Time
}

type Session struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	TokenHash      []byte
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	SessionVersion int64
	UserAgent      string
	IPAddress      string
	CreatedAt      time.Time
}

type UserStore interface {
	Create(ctx context.Context, email, emailNormalized, passwordHash string) (User, error)
	FindByEmail(ctx context.Context, emailNormalized string) (User, error)
	FindByID(ctx context.Context, id uuid.UUID) (User, error)
	MarkLogin(ctx context.Context, id uuid.UUID) error
}

type SessionStore interface {
	Create(ctx context.Context, session Session) error
	FindByID(ctx context.Context, id uuid.UUID) (Session, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeUser(ctx context.Context, userID uuid.UUID) error
}

type contextKey struct{}

func WithUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, contextKey{}, user)
}

func UserFromContext(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(contextKey{}).(User)
	return user, ok
}
