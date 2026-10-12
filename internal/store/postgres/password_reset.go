package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"example.com/go-security-api/internal/auth"
	"example.com/go-security-api/internal/passwordreset"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PasswordResetStore struct {
	database *pgxpool.Pool
}

func NewPasswordResetStore(database *pgxpool.Pool) *PasswordResetStore {
	return &PasswordResetStore{database: database}
}

// CreateToken invalidates any previous outstanding token before creating a new one.
func (s *PasswordResetStore) CreateToken(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	tx, err := s.database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin password reset token transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		UPDATE password_reset_tokens
		SET consumed_at = COALESCE(consumed_at, NOW())
		WHERE user_id = $1 AND consumed_at IS NULL
	`, userID); err != nil {
		return fmt.Errorf("invalidate previous reset tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, tokenHash, expiresAt); err != nil {
		return fmt.Errorf("insert password reset token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit password reset token transaction: %w", err)
	}
	return nil
}

// ConsumeAndReset keeps consumption, password replacement and all session revocations
// in one transaction, so a token cannot be reused after a successful reset.
func (s *PasswordResetStore) ConsumeAndReset(ctx context.Context, tokenHash []byte, passwordHash string) (auth.User, error) {
	tx, err := s.database.Begin(ctx)
	if err != nil {
		return auth.User{}, fmt.Errorf("begin consume reset token transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tokenID uuid.UUID
	var user auth.User
	err = tx.QueryRow(ctx, `
		SELECT prt.id, u.id, u.email, u.email_normalized, u.password_hash, u.role, u.status,
		       u.session_version, u.created_at, u.updated_at, u.last_login_at
		FROM password_reset_tokens AS prt
		JOIN users AS u ON u.id = prt.user_id
		WHERE prt.token_hash = $1
		  AND prt.consumed_at IS NULL
		  AND prt.expires_at > NOW()
		FOR UPDATE OF prt, u
	`, tokenHash).Scan(
		&tokenID, &user.ID, &user.Email, &user.EmailNormalized, &user.PasswordHash, &user.Role, &user.Status,
		&user.SessionVersion, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, passwordreset.ErrInvalidToken
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("find password reset token: %w", err)
	}

	err = tx.QueryRow(ctx, `
		UPDATE users
		SET password_hash = $1, session_version = session_version + 1, updated_at = NOW()
		WHERE id = $2
		RETURNING id, email, email_normalized, password_hash, role, status, session_version, created_at, updated_at, last_login_at
	`, passwordHash, user.ID).Scan(
		&user.ID, &user.Email, &user.EmailNormalized, &user.PasswordHash, &user.Role, &user.Status,
		&user.SessionVersion, &user.CreatedAt, &user.UpdatedAt, &user.LastLoginAt,
	)
	if err != nil {
		return auth.User{}, fmt.Errorf("update password: %w", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = $1", user.ID); err != nil {
		return auth.User{}, fmt.Errorf("revoke user sessions: %w", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE password_reset_tokens SET consumed_at = NOW() WHERE id = $1", tokenID); err != nil {
		return auth.User{}, fmt.Errorf("consume password reset token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.User{}, fmt.Errorf("commit password reset transaction: %w", err)
	}
	return user, nil
}
