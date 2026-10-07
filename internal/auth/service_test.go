package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type fakeUsers struct {
	user      User
	markLogin bool
}

func (f *fakeUsers) Create(_ context.Context, email, normalized, passwordHash string) (User, error) {
	f.user = User{ID: uuid.New(), Email: email, EmailNormalized: normalized, PasswordHash: passwordHash, Role: "user", Status: "active", SessionVersion: 1}
	return f.user, nil
}

func (f *fakeUsers) FindByEmail(_ context.Context, normalized string) (User, error) {
	if f.user.EmailNormalized != normalized {
		return User{}, ErrUserNotFound
	}
	return f.user, nil
}

func (f *fakeUsers) FindByID(_ context.Context, id uuid.UUID) (User, error) {
	if f.user.ID != id {
		return User{}, ErrUserNotFound
	}
	return f.user, nil
}

func (f *fakeUsers) MarkLogin(_ context.Context, _ uuid.UUID) error {
	f.markLogin = true
	return nil
}

type fakeSessions struct {
	sessions map[uuid.UUID]Session
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{sessions: map[uuid.UUID]Session{}}
}

func (f *fakeSessions) Create(_ context.Context, session Session) error {
	f.sessions[session.ID] = session
	return nil
}

func (f *fakeSessions) FindByID(_ context.Context, id uuid.UUID) (Session, error) {
	session, ok := f.sessions[id]
	if !ok {
		return Session{}, ErrNotAuthenticated
	}
	return session, nil
}

func (f *fakeSessions) Revoke(_ context.Context, id uuid.UUID) error {
	session := f.sessions[id]
	now := time.Now()
	session.RevokedAt = &now
	f.sessions[id] = session
	return nil
}

func (f *fakeSessions) RevokeUser(_ context.Context, userID uuid.UUID) error {
	for id, session := range f.sessions {
		if session.UserID == userID {
			now := time.Now()
			session.RevokedAt = &now
			f.sessions[id] = session
		}
	}
	return nil
}

func TestLoginAuthenticateAndLogout(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	users := &fakeUsers{user: User{ID: uuid.New(), Email: "ana@example.com", EmailNormalized: "ana@example.com", PasswordHash: string(hash), Role: "user", Status: "active", SessionVersion: 1}}
	sessions := newFakeSessions()
	service := NewService(users, sessions, Config{PasswordCost: bcrypt.MinCost, SessionTTL: time.Hour})

	user, token, _, err := service.Login(context.Background(), "ANA@example.com", "secret123", "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if user.ID == uuid.Nil || token == "" || !users.markLogin {
		t.Fatal("expected login to create a session and mark the user")
	}

	authenticated, _, err := service.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if authenticated.ID != user.ID {
		t.Fatal("expected authenticated user")
	}

	if err := service.Logout(context.Background(), token); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, _, err := service.Authenticate(context.Background(), token); err == nil {
		t.Fatal("expected revoked session to fail")
	}
}

func TestSessionVersionInvalidatesExistingSession(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	users := &fakeUsers{user: User{ID: uuid.New(), Email: "ana@example.com", EmailNormalized: "ana@example.com", PasswordHash: string(hash), Role: "user", Status: "active", SessionVersion: 1}}
	service := NewService(users, newFakeSessions(), Config{PasswordCost: bcrypt.MinCost, SessionTTL: time.Hour})
	_, token, _, err := service.Login(context.Background(), "ana@example.com", "secret123", "", "")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	users.user.SessionVersion++
	if _, _, err := service.Authenticate(context.Background(), token); err == nil {
		t.Fatal("expected session version change to invalidate the session")
	}
}

func TestRegisterRejectsShortPassword(t *testing.T) {
	service := NewService(&fakeUsers{}, newFakeSessions(), Config{PasswordCost: bcrypt.MinCost})
	if _, err := service.Register(context.Background(), "ana@example.com", "short"); err != ErrInvalidInput {
		t.Fatalf("expected invalid input, got %v", err)
	}
}
