package httpapi

import "testing"

func TestSafeAuditMetadataRemovesSecrets(t *testing.T) {
	metadata := safeAuditMetadata(map[string]any{
		"permission":    "documents.read",
		"password":      "secret123",
		"access_token":  "atk_plaintext",
		"request_reason": "denied",
	})

	if metadata["permission"] != "documents.read" || metadata["request_reason"] != "denied" {
		t.Fatalf("expected safe metadata to be preserved: %#v", metadata)
	}
	if _, ok := metadata["password"]; ok {
		t.Fatal("password should not be recorded")
	}
	if _, ok := metadata["access_token"]; ok {
		t.Fatal("access token should not be recorded")
	}
}
