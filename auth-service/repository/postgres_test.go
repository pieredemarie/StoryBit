package repository

import (
	"context"
	"database/sql"
	"errors"
	"storybit/auth-service/services"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"
)

func mockStore(t *testing.T) (*PostgresStore, sqlmock.Sqlmock) {
	t.Helper()
	db, m, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &PostgresStore{db: db}, m
}
func TestPostgresUsers(t *testing.T) {
	ctx := context.Background()
	s, m := mockStore(t)
	m.ExpectExec("INSERT INTO auth.users").WithArgs(sqlmock.AnyArg(), "writer", "w@example.com", "hash").WillReturnResult(sqlmock.NewResult(0, 1))
	u, err := s.CreateUser(ctx, services.User{Username: "writer", Email: "w@example.com", PasswordHash: "hash"})
	if err != nil || u.ID == "" {
		t.Fatalf("create: %v", err)
	}
	m.ExpectExec("INSERT INTO auth.users").WillReturnError(&pgconn.PgError{Code: "23505"})
	if _, err = s.CreateUser(ctx, services.User{}); !errors.Is(err, services.ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	rows := sqlmock.NewRows([]string{"id", "username", "email", "password_hash"}).AddRow(u.ID, "writer", "w@example.com", "hash")
	m.ExpectQuery("SELECT id::text,username,email,password_hash FROM auth.users WHERE lower").WithArgs("w@example.com").WillReturnRows(rows)
	if got, err := s.UserByEmail(ctx, "w@example.com"); err != nil || got.ID != u.ID {
		t.Fatalf("by email: %v", err)
	}
	m.ExpectQuery("SELECT id::text,username,email,password_hash FROM auth.users WHERE id").WithArgs(u.ID).WillReturnError(sql.ErrNoRows)
	if _, err := s.UserByID(ctx, u.ID); !errors.Is(err, services.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	rows = sqlmock.NewRows([]string{"id", "username", "email", "password_hash"}).AddRow(u.ID, "new", "w@example.com", "hash")
	m.ExpectQuery("UPDATE auth.users SET username").WithArgs(u.ID, "new").WillReturnRows(rows)
	if got, err := s.UpdateUsername(ctx, u.ID, "new"); err != nil || got.Username != "new" {
		t.Fatalf("update: %v", err)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestPostgresSessions(t *testing.T) {
	ctx := context.Background()
	s, m := mockStore(t)
	expiry := time.Now().Add(time.Hour)
	m.ExpectExec("INSERT INTO auth.refresh_sessions").WithArgs(sqlmock.AnyArg(), "user-1", "old", expiry).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := s.SaveSession(ctx, "user-1", "old", expiry); err != nil {
		t.Fatal(err)
	}
	m.ExpectBegin()
	m.ExpectQuery("UPDATE auth.refresh_sessions SET revoked_at=now").WithArgs("old").WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow("user-1"))
	m.ExpectExec("INSERT INTO auth.refresh_sessions").WithArgs(sqlmock.AnyArg(), "user-1", "new", expiry).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	if id, err := s.RotateSession(ctx, "old", "new", expiry); err != nil || id != "user-1" {
		t.Fatalf("rotate: %s %v", id, err)
	}
	m.ExpectBegin()
	m.ExpectQuery("UPDATE auth.refresh_sessions SET revoked_at=now").WithArgs("old").WillReturnError(sql.ErrNoRows)
	m.ExpectRollback()
	if _, err := s.RotateSession(ctx, "old", "next", expiry); !errors.Is(err, services.ErrInvalidSession) {
		t.Fatalf("replay: %v", err)
	}
	m.ExpectExec("UPDATE auth.refresh_sessions SET revoked_at=now").WithArgs("new", "user-1").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := s.RevokeSession(ctx, "new", "user-1"); err != nil {
		t.Fatal(err)
	}
	m.ExpectExec("UPDATE auth.refresh_sessions SET revoked_at=now").WithArgs("new", "user-1").WillReturnResult(sqlmock.NewResult(0, 0))
	if err := s.RevokeSession(ctx, "new", "user-1"); !errors.Is(err, services.ErrInvalidSession) {
		t.Fatalf("revoked: %v", err)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresFailurePaths(t *testing.T) {
	ctx := context.Background()
	s, m := mockStore(t)
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	m.ExpectQuery("SELECT id::text,username,email,password_hash FROM auth.users WHERE lower").WithArgs("absent@example.com").WillReturnError(sql.ErrNoRows)
	if _, err := s.UserByEmail(ctx, "absent@example.com"); !errors.Is(err, services.ErrNotFound) {
		t.Fatalf("missing email: %v", err)
	}
	m.ExpectQuery("UPDATE auth.users SET username").WithArgs("id", "taken").WillReturnError(&pgconn.PgError{Code: "23505"})
	if _, err := s.UpdateUsername(ctx, "id", "taken"); !errors.Is(err, services.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	m.ExpectExec("INSERT INTO auth.refresh_sessions").WillReturnError(errors.New("database unavailable"))
	if err := s.SaveSession(ctx, "id", "hash", time.Now()); err == nil {
		t.Fatal("expected database error")
	}
	m.ExpectBegin()
	m.ExpectQuery("UPDATE auth.refresh_sessions SET revoked_at=now").WithArgs("old").WillReturnError(errors.New("database unavailable"))
	m.ExpectRollback()
	if _, err := s.RotateSession(ctx, "old", "new", time.Now()); err == nil {
		t.Fatal("expected rotation error")
	}
	m.ExpectExec("UPDATE auth.refresh_sessions SET revoked_at=now").WithArgs("hash", "id").WillReturnError(errors.New("database unavailable"))
	if err := s.RevokeSession(ctx, "hash", "id"); err == nil {
		t.Fatal("expected revoke error")
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresMorePaths(t *testing.T) {
	ctx := context.Background()
	s, m := mockStore(t)
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	m.ExpectQuery("SELECT id::text,username,email,password_hash FROM auth.users WHERE id").WithArgs("some-id").WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password_hash"}).AddRow("some-id", "writer", "w@example.com", "hash"))
	if u, err := s.UserByID(ctx, "some-id"); err != nil || u.Username != "writer" {
		t.Fatalf("lookup: %v", err)
	}
	m.ExpectQuery("UPDATE auth.users SET username").WithArgs("missing", "new").WillReturnError(sql.ErrNoRows)
	if _, err := s.UpdateUsername(ctx, "missing", "new"); !errors.Is(err, services.ErrNotFound) {
		t.Fatalf("missing update: %v", err)
	}
	m.ExpectExec("INSERT INTO auth.users").WillReturnError(errors.New("disk error"))
	if _, err := s.CreateUser(ctx, services.User{}); err == nil {
		t.Fatal("expected write error")
	}
	m.ExpectBegin()
	m.ExpectQuery("UPDATE auth.refresh_sessions SET revoked_at=now").WithArgs("old").WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow("user-1"))
	m.ExpectExec("INSERT INTO auth.refresh_sessions").WillReturnError(errors.New("disk error"))
	m.ExpectRollback()
	if _, err := s.RotateSession(ctx, "old", "new", time.Now()); err == nil {
		t.Fatal("expected insert error")
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestOpenPostgresUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := OpenPostgres(ctx, "postgres://invalid:invalid@127.0.0.1:1/storybit?connect_timeout=1"); err == nil {
		t.Fatal("expected connection failure")
	}
}
