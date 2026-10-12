package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"example.com/go-security-api/internal/auth"
	"example.com/go-security-api/internal/passwordreset"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func TestHealthz(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	NewHandler(nil, nil, nil, nil, nil, nil, false).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if recorder.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("expected JSON content type, got %q", recorder.Header().Get("Content-Type"))
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("expected security header")
	}

	var response map[string]string
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["status"] != "ok" {
		t.Fatalf("expected ok status, got %q", response["status"])
	}
	if response["request_id"] == "" {
		t.Fatal("expected request id")
	}
}

func TestRequestIDIsPropagated(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.Header.Set("X-Request-ID", "test-request-id")

	NewHandler(nil, nil, nil, nil, nil, nil, false).ServeHTTP(recorder, request)

	if got := recorder.Header().Get("X-Request-ID"); got != "test-request-id" {
		t.Fatalf("expected propagated request id, got %q", got)
	}
}

func TestReadyzWithoutDatabaseIsUnavailable(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)

	NewHandler(nil, nil, nil, nil, nil, nil, false).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", recorder.Code)
	}
}

type passwordResetHTTPUsers struct{ user auth.User }

func (f passwordResetHTTPUsers) FindByEmail(_ context.Context, email string) (auth.User, error) {
	if email != f.user.EmailNormalized {
		return auth.User{}, auth.ErrUserNotFound
	}
	return f.user, nil
}

type passwordResetHTTPStore struct {
	user   auth.User
	record map[string]time.Time
}

func (f *passwordResetHTTPStore) CreateToken(_ context.Context, _ uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	f.record = map[string]time.Time{string(tokenHash): expiresAt}
	return nil
}

func (f *passwordResetHTTPStore) ConsumeAndReset(_ context.Context, tokenHash []byte, passwordHash string) (auth.User, error) {
	expiresAt, ok := f.record[string(tokenHash)]
	if !ok || !time.Now().UTC().Before(expiresAt) {
		return auth.User{}, passwordreset.ErrInvalidToken
	}
	delete(f.record, string(tokenHash))
	f.user.PasswordHash = passwordHash
	f.user.SessionVersion++
	return f.user, nil
}

type passwordResetHTTPMailer struct{ token string }

func (f *passwordResetHTTPMailer) Available() bool { return true }
func (f *passwordResetHTTPMailer) SendResetLink(_ context.Context, _ string, token string, _ time.Time) error {
	f.token = token
	return nil
}

func TestPasswordResetHTTPFlowIsOpaqueAndSingleUse(t *testing.T) {
	user := auth.User{ID: uuid.New(), Email: "ana@example.com", EmailNormalized: "ana@example.com", Status: "active"}
	store := &passwordResetHTTPStore{user: user}
	mailer := &passwordResetHTTPMailer{}
	resetService := passwordreset.NewService(passwordResetHTTPUsers{user: user}, store, mailer, nil, bcrypt.MinCost, time.Hour)
	handler := NewHandler(nil, nil, resetService, nil, nil, nil, false)

	for _, email := range []string{"ana@example.com", "missing@example.com"} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/forgot", strings.NewReader(`{"email":"`+email+`"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("expected opaque 202 for %q, got %d", email, response.Code)
		}
	}

	if mailer.token == "" {
		t.Fatal("expected a reset token for the known user")
	}
	tokenHash := sha256.Sum256([]byte(mailer.token))
	if _, ok := store.record[string([]byte(mailer.token))]; ok {
		t.Fatal("reset token must not be persisted in plaintext")
	}
	if _, ok := store.record[string(tokenHash[:])]; !ok {
		t.Fatal("expected reset token hash to be persisted")
	}

	resetRequest := `{"token":"` + mailer.token + `","password":"new-secret-123"}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset", strings.NewReader(resetRequest)))
	if response.Code != http.StatusNoContent {
		t.Fatalf("expected reset success, got %d", response.Code)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/reset", strings.NewReader(resetRequest)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected consumed token to fail, got %d", response.Code)
	}
}
