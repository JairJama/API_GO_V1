package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	NewHandler(nil, nil, nil, nil, nil, false).ServeHTTP(recorder, request)

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

	NewHandler(nil, nil, nil, nil, nil, false).ServeHTTP(recorder, request)

	if got := recorder.Header().Get("X-Request-ID"); got != "test-request-id" {
		t.Fatalf("expected propagated request id, got %q", got)
	}
}

func TestReadyzWithoutDatabaseIsUnavailable(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)

	NewHandler(nil, nil, nil, nil, nil, false).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", recorder.Code)
	}
}
