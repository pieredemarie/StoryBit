package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeRepository struct {
	users    map[string]User
	sessions map[string]string
}

func (f *fakeRepository) Ping(context.Context) error { return nil }
func (f *fakeRepository) CreateUser(_ context.Context, u User) (User, error) {
	for _, v := range f.users {
		if v.Email == u.Email {
			return User{}, ErrConflict
		}
	}
	u.ID = "user-1"
	f.users[u.ID] = u
	return u, nil
}
func (f *fakeRepository) UserByEmail(_ context.Context, email string) (User, error) {
	for _, u := range f.users {
		if u.Email == email {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}
func (f *fakeRepository) UserByID(_ context.Context, id string) (User, error) {
	u, ok := f.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}
func (f *fakeRepository) UpdateUsername(_ context.Context, id, name string) (User, error) {
	u, ok := f.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	u.Username = name
	f.users[id] = u
	return u, nil
}
func (f *fakeRepository) SaveSession(_ context.Context, id, hash string, _ time.Time) error {
	f.sessions[hash] = id
	return nil
}
func (f *fakeRepository) RotateSession(_ context.Context, old, new string, _ time.Time) (string, error) {
	id, ok := f.sessions[old]
	if !ok {
		return "", ErrInvalidSession
	}
	delete(f.sessions, old)
	f.sessions[new] = id
	return id, nil
}
func (f *fakeRepository) RevokeSession(_ context.Context, hash, id string) error {
	if f.sessions[hash] != id {
		return ErrInvalidSession
	}
	delete(f.sessions, hash)
	return nil
}

func TestRegisterLoginRefreshLogout(t *testing.T) {
	repo := &fakeRepository{users: map[string]User{}, sessions: map[string]string{}}
	svc := NewAuthService(repo, []byte("12345678901234567890123456789012"))
	u, err := svc.Register(context.Background(), "Writer", "WRITER@example.com", "long-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "writer@example.com" || u.PasswordHash != "" {
		t.Fatalf("unsafe user response: %#v", u)
	}
	if _, err := svc.Register(context.Background(), "Other", "writer@example.com", "long-password-123"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := svc.Login(context.Background(), "writer@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	tok, err := svc.Login(context.Background(), "writer@example.com", "long-password-123")
	if err != nil || tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("login: %v", err)
	}
	id, err := svc.VerifyAccess(tok.AccessToken)
	if err != nil || id != u.ID {
		t.Fatalf("jwt: %s %v", id, err)
	}
	rotated, err := svc.Refresh(context.Background(), tok.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(context.Background(), tok.RefreshToken); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("replay: %v", err)
	}
	if err := svc.Logout(context.Background(), id, rotated.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(context.Background(), rotated.RefreshToken); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("logout: %v", err)
	}
}

func TestAuthServiceValidationAndProfile(t *testing.T) {
	ctx := context.Background()
	repo := &fakeRepository{users: map[string]User{}, sessions: map[string]string{}}
	svc := NewAuthService(repo, []byte("12345678901234567890123456789012"))
	if err := svc.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ name, email, password string }{
		{"", "u@example.com", "long-password-123"},
		{"user", "bad-email", "long-password-123"},
		{"user", "u@example.com", "short"},
		{"user", "u@example.com", "long-password-" + string(make([]byte, 73))},
	} {
		if _, err := svc.Register(ctx, v.name, v.email, v.password); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("registration validation: %v", err)
		}
	}
	if _, err := svc.Login(ctx, "", "password"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty login: %v", err)
	}
	if _, err := svc.Login(ctx, "absent@example.com", "password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown login: %v", err)
	}
	if _, err := svc.Refresh(ctx, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty refresh: %v", err)
	}
	if err := svc.Logout(ctx, "id", ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty logout: %v", err)
	}
	if _, err := svc.VerifyAccess("malformed"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("invalid jwt: %v", err)
	}
	if _, err := svc.Profile(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing profile: %v", err)
	}
	if _, err := svc.UpdateProfile(ctx, "missing", ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid profile: %v", err)
	}
	if _, err := svc.UpdateProfile(ctx, "missing", "valid"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing update: %v", err)
	}
	u, err := svc.Register(ctx, "  writer  ", " W@example.com ", "long-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "writer" || u.Email != "w@example.com" {
		t.Fatalf("normalization: %#v", u)
	}
	p, err := svc.Profile(ctx, u.ID)
	if err != nil || p.PasswordHash != "" {
		t.Fatalf("profile privacy: %v", err)
	}
	p, err = svc.UpdateProfile(ctx, u.ID, "  renamed  ")
	if err != nil || p.Username != "renamed" || p.PasswordHash != "" {
		t.Fatalf("update: %#v %v", p, err)
	}
}
