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

	"storybit/auth-service/internal/handlers"
	"storybit/auth-service/repository"
	"storybit/auth-service/services"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	secret := os.Getenv("AUTH_JWT_SECRET")
	if len(secret) < 32 {
		logger.Error("AUTH_JWT_SECRET must be at least 32 bytes")
		os.Exit(1)
	}
	addr := os.Getenv("AUTH_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	dsn := os.Getenv("AUTH_DATABASE_URL")
	if dsn == "" {
		logger.Error("AUTH_DATABASE_URL is required")
		os.Exit(1)
	}
	store, err := repository.OpenPostgres(context.Background(), dsn)
	if err != nil {
		logger.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	svc := services.NewAuthService(store, []byte(secret))
	srv := &http.Server{Addr: addr, Handler: handlers.New(logger, svc), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown failed", "error", err)
		}
	}()
	logger.Info("auth service starting", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}
