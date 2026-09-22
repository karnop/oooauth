package main

import (
	"auth/internal/auth"
	"auth/internal/config"
	"auth/internal/database"
	internalhttp "auth/internal/http"
	"auth/internal/mailer"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// load configs
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("configuration loaded",
		"port", cfg.Port,
		"env", cfg.Environment,
		"cookie_secure", cfg.CookieSecure,
	)

	// initializing postgreSql connection pool
	db, err := database.New(cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}

	defer db.Close()
	slog.Info("database connection pool initialized")

	// initializing repos and services
	userRepo := database.NewUserRepository(db.Pool)
	sessionRepo := database.NewSessionRepository(db.Pool)
	tokenRepo := database.NewVerificationTokenRepository(db.Pool)

	frontendURL := "http://localhost:3000"
	if len(cfg.AllowedOrigins) > 0 && cfg.AllowedOrigins[0] != "" {
		frontendURL = cfg.AllowedOrigins[0]
	}
	devMailer := mailer.NewDevMailer(frontendURL)

	authService := auth.NewService(userRepo, sessionRepo, tokenRepo, devMailer, cfg)

	// assembling http router
	router := internalhttp.NewRouter(cfg, db, authService)

	// http server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// starting server
	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("server starting", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	// graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		slog.Error("server failed to start", "error", err)
		os.Exit(1)

	case sig := <-shutdown:
		slog.Info("shutdown signal received", "signal", sig.String())
		// allowing 15 seconds for active requests
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown failed, forcing server close", "error", err)
			_ = server.Close()
		}
		slog.Info("server stopped cleanly")
	}
}
