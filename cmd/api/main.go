package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/go-security-api/internal/access"
	"example.com/go-security-api/internal/audit"
	"example.com/go-security-api/internal/auth"
	"example.com/go-security-api/internal/config"
	"example.com/go-security-api/internal/httpapi"
	"example.com/go-security-api/internal/migrations"
	"example.com/go-security-api/internal/passwordreset"
	"example.com/go-security-api/internal/resources"
	"example.com/go-security-api/internal/serviceaccounts"
	"example.com/go-security-api/internal/store/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}

	database, err := postgres.Open(context.Background(), cfg.DatabaseURL, cfg.DBMaxConns)
	if err != nil {
		logger.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	if err := migrations.Run(context.Background(), database); err != nil {
		logger.Error("database migrations failed", "error", err)
		os.Exit(1)
	}
	authentication := auth.NewService(
		postgres.NewUserStore(database),
		postgres.NewSessionStore(database),
		auth.Config{PasswordCost: cfg.PasswordCost, SessionTTL: cfg.SessionTTL},
	)
	authorization := access.NewService(postgres.NewPermissionStore(database))
	auditor := audit.NewService(postgres.NewAuditStore(database))
	var resetMailer passwordreset.PasswordResetMailer = passwordreset.NewUnavailableMailer()
	if cfg.AppEnvironment == "development" {
		resetMailer = passwordreset.NewLogMailer(logger, cfg.PasswordResetURLBase)
	}
	resetService := passwordreset.NewService(
		postgres.NewUserStore(database),
		postgres.NewPasswordResetStore(database),
		resetMailer,
		passwordreset.NewMemoryLimiter(3, 5, 15*time.Minute),
		cfg.PasswordCost,
		cfg.PasswordResetTTL,
	)
	serviceAccounts, err := serviceaccounts.NewService(postgres.NewServiceAccountStore(database), cfg.APITokenPepper)
	if err != nil {
		logger.Error("service account configuration failed", "error", err)
		os.Exit(1)
	}
	resourceService := resources.NewService(
		postgres.NewOrganizationStore(database),
		postgres.NewDocumentStore(database),
		authorization,
	)

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpapi.NewHandler(database, authentication, resetService, serviceAccounts, authorization, resourceService, auditor, cfg.CookieSecure),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown failed", "error", err)
		}
	}()

	logger.Info("api server listening", "addr", cfg.HTTPAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("api server stopped unexpectedly", "error", err)
		os.Exit(1)
	}
}
