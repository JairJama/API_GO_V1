package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr     string
	DatabaseURL  string
	DBMaxConns   int32
	PasswordCost int
	SessionTTL   time.Duration
	CookieSecure bool
}

func Load() (Config, error) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}

	passwordCost, err := integerEnv("BCRYPT_COST", 12)
	if err != nil {
		return Config{}, err
	}
	sessionTTL, err := durationEnv("SESSION_TTL", 12*time.Hour)
	if err != nil {
		return Config{}, err
	}
	cookieSecure, err := booleanEnv("COOKIE_SECURE", false)
	if err != nil {
		return Config{}, err
	}

	return Config{
		HTTPAddr:     getenv("HTTP_ADDR", ":8080"),
		DatabaseURL:  databaseURL,
		DBMaxConns:   4,
		PasswordCost: passwordCost,
		SessionTTL:   sessionTTL,
		CookieSecure: cookieSecure,
	}, nil
}

func integerEnv(key string, fallback int) (int, error) {
	value := getenv(key, "")
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, errors.New(key + " must be a positive integer")
	}
	return parsed, nil
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := getenv(key, "")
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, errors.New(key + " must be a positive duration")
	}
	return parsed, nil
}

func booleanEnv(key string, fallback bool) (bool, error) {
	value := getenv(key, "")
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, errors.New(key + " must be true or false")
	}
	return parsed, nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
