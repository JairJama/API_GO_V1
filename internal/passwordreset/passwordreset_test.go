package passwordreset

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"example.com/go-security-api/internal/auth"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type fakeUsers struct{ user auth.User }

func (f fakeUsers) FindByEmail(_ context.Context, email string) (auth.User, error) {
	if email != f.user.EmailNormalized {
		return auth.User{}, auth.ErrUserNotFound
	}
	return f.user, nil
}

type resetRecord struct {
	userID    uuid.UUID
	hash      []byte
	expiresAt time.Time
	consumed  bool
}

type fakeStore struct {
	now     func() time.Time
	users   map[uuid.UUID]auth.User
	records []resetRecord
}

func (f *fakeStore) CreateToken(_ context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	for index := range f.records {
		if f.records[index].userID == userID && !f.records[index].consumed {
			f.records[index].consumed = true
		}
	}
	f.records = append(f.records, resetRecord{userID: userID, hash: append([]byte(nil), tokenHash...), expiresAt: expiresAt})
	return nil
}

func (f *fakeStore) ConsumeAndReset(_ context.Context, tokenHash []byte, passwordHash string) (auth.User, error) {
	for index := range f.records {
		record := &f.records[index]
		if string(record.hash) != string(tokenHash) || record.consumed || !f.now().Before(record.expiresAt) {
			continue
		}
		record.consumed = true
		user := f.users[record.userID]
		user.PasswordHash = passwordHash
		user.SessionVersion++
		f.users[user.ID] = user
		return user, nil
	}
	return auth.User{}, ErrInvalidToken
}

type fakeMailer struct {
	available bool
	tokens    []string
}

func (f *fakeMailer) Available() bool { return f.available }
func (f *fakeMailer) SendResetLink(_ context.Context, _ string, token string, _ time.Time) error {
	f.tokens = append(f.tokens, token)
	return nil
}

func TestResetTokenIsHashedSingleUseAndRevokesPreviousPassword(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	user := auth.User{ID: uuid.New(), Email: "ana@example.com", EmailNormalized: "ana@example.com", Status: "active", SessionVersion: 4}
	store := &fakeStore{now: func() time.Time { return now }, users: map[uuid.UUID]auth.User{user.ID: user}}
	mailer := &fakeMailer{available: true}
	service := NewService(fakeUsers{user: user}, store, mailer, NewMemoryLimiter(3, 5, 15*time.Minute), bcrypt.MinCost, time.Hour)
	service.now = func() time.Time { return now }

	if _, err := service.Request(context.Background(), user.Email, "127.0.0.1"); err != nil {
		t.Fatalf("request reset: %v", err)
	}
	if len(mailer.tokens) != 1 || len(store.records) != 1 {
		t.Fatal("expected one delivered and stored reset token")
	}
	plainToken := mailer.tokens[0]
	if string(store.records[0].hash) == plainToken {
		t.Fatal("reset token must not be stored in plaintext")
	}
	expectedHash := sha256.Sum256([]byte(plainToken))
	if string(store.records[0].hash) != string(expectedHash[:]) {
		t.Fatal("expected SHA-256 hash to be stored")
	}

	updated, err := service.Reset(context.Background(), plainToken, "new-secret-123")
	if err != nil {
		t.Fatalf("reset password: %v", err)
	}
	if updated.SessionVersion != 5 {
		t.Fatalf("expected session version increment, got %d", updated.SessionVersion)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("new-secret-123")) != nil {
		t.Fatal("expected new password hash")
	}
	if _, err := service.Reset(context.Background(), plainToken, "another-secret-123"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected a consumed token to fail, got %v", err)
	}
}

func TestNewTokenInvalidatesPreviousTokenAndExpiredTokenFails(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	user := auth.User{ID: uuid.New(), Email: "ana@example.com", EmailNormalized: "ana@example.com", Status: "active"}
	store := &fakeStore{now: func() time.Time { return now }, users: map[uuid.UUID]auth.User{user.ID: user}}
	mailer := &fakeMailer{available: true}
	service := NewService(fakeUsers{user: user}, store, mailer, NewMemoryLimiter(10, 10, time.Hour), bcrypt.MinCost, time.Hour)
	service.now = func() time.Time { return now }

	_, _ = service.Request(context.Background(), user.Email, "127.0.0.1")
	first := mailer.tokens[0]
	_, _ = service.Request(context.Background(), user.Email, "127.0.0.2")
	second := mailer.tokens[1]
	if _, err := service.Reset(context.Background(), first, "new-secret-123"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected previous token to be invalid, got %v", err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := service.Reset(context.Background(), second, "new-secret-123"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected expired token to fail, got %v", err)
	}
}

func TestRequestRateLimitKeepsUnknownEmailOpaque(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	user := auth.User{ID: uuid.New(), Email: "ana@example.com", EmailNormalized: "ana@example.com", Status: "active"}
	store := &fakeStore{now: func() time.Time { return now }, users: map[uuid.UUID]auth.User{user.ID: user}}
	mailer := &fakeMailer{available: true}
	service := NewService(fakeUsers{user: user}, store, mailer, NewMemoryLimiter(3, 5, 15*time.Minute), bcrypt.MinCost, time.Hour)
	service.now = func() time.Time { return now }

	for attempt := 0; attempt < 3; attempt++ {
		result, err := service.Request(context.Background(), "missing@example.com", "127.0.0.1")
		if err != nil || result.RateLimited {
			t.Fatalf("attempt %d unexpectedly limited: result=%#v err=%v", attempt, result, err)
		}
	}
	result, err := service.Request(context.Background(), "missing@example.com", "127.0.0.1")
	if err != nil || !result.RateLimited {
		t.Fatalf("expected opaque rate limit, got result=%#v err=%v", result, err)
	}
}

func TestLogMailerRejectsInvalidURLAsUnavailable(t *testing.T) {
	mailer := NewLogMailer(nil, "not a URL")
	if mailer.Available() {
		t.Fatal("expected invalid reset URL to make the mailer unavailable")
	}
	if err := mailer.SendResetLink(context.Background(), "ana@example.com", "prt_token", time.Now()); !errors.Is(err, ErrMailerUnavailable) {
		t.Fatalf("expected unavailable mailer error, got %v", err)
	}
}
