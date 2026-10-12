package config

import "testing"

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected DATABASE_URL validation error")
	}
}

func TestLoadUsesEnvironment(t *testing.T) {
	t.Setenv("HTTP_ADDR", ":9090")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("API_TOKEN_PEPPER", "test-pepper")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.HTTPAddr != ":9090" {
		t.Fatalf("expected HTTP_ADDR from environment, got %q", cfg.HTTPAddr)
	}
	if cfg.PasswordResetTTL.String() != "1h0m0s" || cfg.AppEnvironment != "development" {
		t.Fatalf("unexpected password reset defaults: %#v", cfg)
	}
}

func TestLoadReadsPasswordResetConfiguration(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("APP_ENV", "production")
	t.Setenv("PASSWORD_RESET_TTL", "30m")
	t.Setenv("PASSWORD_RESET_URL_BASE", "https://api.example.test")
	t.Setenv("API_TOKEN_PEPPER", "test-pepper")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.PasswordResetTTL.String() != "30m0s" || cfg.PasswordResetURLBase != "https://api.example.test" || cfg.AppEnvironment != "production" {
		t.Fatalf("unexpected password reset configuration: %#v", cfg)
	}
}

func TestLoadRequiresAPITokenPepper(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("API_TOKEN_PEPPER", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected API_TOKEN_PEPPER validation error")
	}
}
