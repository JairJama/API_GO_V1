package postgres

import (
	"context"
	"errors"
	"fmt"

	"example.com/go-security-api/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserStore struct {
	database *pgxpool.Pool
}

func NewUserStore(database *pgxpool.Pool) *UserStore {
	return &UserStore{database: database}
}

func (s *UserStore) Create(ctx context.Context, email, emailNormalized, passwordHash string) (auth.User, error) {
	tx, err := s.database.Begin(ctx)
	if err != nil {
		return auth.User{}, fmt.Errorf("begin create user transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var user auth.User
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email, email_normalized, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, email, email_normalized, password_hash, role, status, session_version, created_at, updated_at, last_login_at
	`, email, emailNormalized, passwordHash).Scan(
		&user.ID, &user.Email, &user.EmailNormalized, &user.PasswordHash, &user.Role, &user.Status,
		&user.SessionVersion, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
	)
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return auth.User{}, auth.ErrEmailExists
		}
		return auth.User{}, fmt.Errorf("create user: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, id FROM roles WHERE name = 'user'
		ON CONFLICT DO NOTHING
	`, user.ID)
	if err != nil {
		return auth.User{}, fmt.Errorf("assign default user role: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.User{}, fmt.Errorf("commit create user transaction: %w", err)
	}
	return user, nil
}

func (s *UserStore) FindByEmail(ctx context.Context, emailNormalized string) (auth.User, error) {
	return s.find(ctx, `
		SELECT id, email, email_normalized, password_hash, role, status, session_version, created_at, updated_at, last_login_at
		FROM users WHERE email_normalized = $1
	`, emailNormalized)
}

func (s *UserStore) FindByID(ctx context.Context, id uuid.UUID) (auth.User, error) {
	return s.find(ctx, `
		SELECT id, email, email_normalized, password_hash, role, status, session_version, created_at, updated_at, last_login_at
		FROM users WHERE id = $1
	`, id)
}

func (s *UserStore) find(ctx context.Context, query string, args ...any) (auth.User, error) {
	var user auth.User
	err := s.database.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Email, &user.EmailNormalized, &user.PasswordHash, &user.Role, &user.Status,
		&user.SessionVersion, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("find user: %w", err)
	}
	return user, nil
}

func (s *UserStore) MarkLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.database.Exec(ctx, "UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("mark login: %w", err)
	}
	return nil
}

type SessionStore struct {
	database *pgxpool.Pool
}

func NewSessionStore(database *pgxpool.Pool) *SessionStore {
	return &SessionStore{database: database}
}

func (s *SessionStore) Create(ctx context.Context, session auth.Session) error {
	_, err := s.database.Exec(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at, session_version, user_agent, ip_address)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, session.ID, session.UserID, session.TokenHash, session.ExpiresAt, session.SessionVersion, session.UserAgent, session.IPAddress)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *SessionStore) FindByID(ctx context.Context, id uuid.UUID) (auth.Session, error) {
	var session auth.Session
	err := s.database.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, revoked_at, session_version, user_agent, ip_address, created_at
		FROM sessions WHERE id = $1
	`, id).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &session.ExpiresAt, &session.RevokedAt,
		&session.SessionVersion, &session.UserAgent, &session.IPAddress, &session.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Session{}, auth.ErrNotAuthenticated
	}
	if err != nil {
		return auth.Session{}, fmt.Errorf("find session: %w", err)
	}
	return session, nil
}

func (s *SessionStore) Revoke(ctx context.Context, id uuid.UUID) error {
	_, err := s.database.Exec(ctx, "UPDATE sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (s *SessionStore) RevokeUser(ctx context.Context, userID uuid.UUID) error {
	_, err := s.database.Exec(ctx, "UPDATE sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	return nil
}
