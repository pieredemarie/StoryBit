package handlers

import (
	"context"
	"github.com/google/uuid"
	"log/slog"
	"net/http"
	"storybit/auth-service/services"
	"strings"
	"sync"
	"time"
)

type User = services.User
type fakeRepository struct {
	mu       sync.Mutex
	users    map[string]User
	sessions map[string]fakeSession
}
type fakeSession struct {
	id      string
	expires time.Time
}

func newFakeRepository() *fakeRepository {
	return &fakeRepository{users: map[string]User{}, sessions: map[string]fakeSession{}}
}
func (*fakeRepository) Ping(context.Context) error { return nil }
func (f *fakeRepository) CreateUser(_ context.Context, u User) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.users {
		if strings.EqualFold(v.Email, u.Email) || strings.EqualFold(v.Username, u.Username) {
			return User{}, services.ErrConflict
		}
	}
	u.ID = uuid.NewString()
	f.users[u.ID] = u
	return u, nil
}
func (f *fakeRepository) UserByEmail(_ context.Context, email string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.users {
		if strings.EqualFold(v.Email, email) {
			return v, nil
		}
	}
	return User{}, services.ErrNotFound
}
func (f *fakeRepository) UserByID(_ context.Context, id string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.users[id]
	if !ok {
		return User{}, services.ErrNotFound
	}
	return v, nil
}
func (f *fakeRepository) UpdateUsername(_ context.Context, id, name string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.users[id]
	if !ok {
		return User{}, services.ErrNotFound
	}
	for _, u := range f.users {
		if u.ID != id && strings.EqualFold(u.Username, name) {
			return User{}, services.ErrConflict
		}
	}
	v.Username = name
	f.users[id] = v
	return v, nil
}
func (f *fakeRepository) SaveSession(_ context.Context, id, hash string, expires time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[hash] = fakeSession{id: id, expires: expires}
	return nil
}
func (f *fakeRepository) RotateSession(_ context.Context, old, new string, expires time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.sessions[old]
	if !ok || time.Now().After(v.expires) {
		return "", services.ErrInvalidSession
	}
	delete(f.sessions, old)
	f.sessions[new] = fakeSession{id: v.id, expires: expires}
	return v.id, nil
}
func (f *fakeRepository) RevokeSession(_ context.Context, hash, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.sessions[hash]
	if !ok || v.id != id {
		return services.ErrInvalidSession
	}
	delete(f.sessions, hash)
	return nil
}
func NewForTest(logger *slog.Logger, secret []byte) http.Handler {
	return New(logger, services.NewAuthService(newFakeRepository(), secret))
}
