package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthJourney(t *testing.T) {
	app := NewForTest(slog.Default(), []byte(strings.Repeat("s", 32)))
	call := func(method, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		return w
	}
	reg := call("POST", "/auth/register", `{"username":"writer","email":"WRITER@example.com","password":"long-password-123"}`, "")
	if reg.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", reg.Code, reg.Body.String())
	}
	duplicate := call("POST", "/auth/register", `{"username":"other","email":"writer@example.com","password":"long-password-123"}`, "")
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", duplicate.Code)
	}
	bad := call("POST", "/auth/login", `{"email":"writer@example.com","password":"wrong-password"}`, "")
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: %d", bad.Code)
	}
	login := call("POST", "/auth/login", `{"email":"writer@example.com","password":"long-password-123"}`, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login: %d %s", login.Code, login.Body.String())
	}
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("tokens missing")
	}
	parsed, err := jwt.Parse(tokens.AccessToken, func(token *jwt.Token) (any, error) { return []byte(strings.Repeat("s", 32)), nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("invalid JWT: %v", err)
	}
	me := call("GET", "/users/me", "", tokens.AccessToken)
	if me.Code != http.StatusOK {
		t.Fatalf("me: %d", me.Code)
	}
	refreshed := call("POST", "/auth/refresh", `{"refresh_token":"`+tokens.RefreshToken+`"}`, "")
	if refreshed.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", refreshed.Code, refreshed.Body.String())
	}
	replay := call("POST", "/auth/refresh", `{"refresh_token":"`+tokens.RefreshToken+`"}`, "")
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("replayed refresh: %d", replay.Code)
	}
	var rotated struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(refreshed.Body.Bytes(), &rotated)
	out := call("POST", "/auth/logout", `{"refresh_token":"`+rotated.RefreshToken+`"}`, tokens.AccessToken)
	if out.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", out.Code)
	}
	after := call("POST", "/auth/refresh", `{"refresh_token":"`+rotated.RefreshToken+`"}`, "")
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("logout did not revoke: %d", after.Code)
	}
}

func TestProfileAndValidation(t *testing.T) {
	app := NewForTest(slog.Default(), []byte(strings.Repeat("k", 32)))
	call := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w
	}
	if got := call("POST", "/auth/register", `{"username":"x","email":"bad","password":"short"}`, ""); got.Code != 400 {
		t.Fatalf("invalid registration: %d", got.Code)
	}
	if got := call("GET", "/users/me", "", ""); got.Code != 401 {
		t.Fatalf("unauthorized profile: %d", got.Code)
	}
	if got := call("GET", "/users/me", "", "invalid"); got.Code != 401 {
		t.Fatalf("invalid jwt: %d", got.Code)
	}
	reg := call("POST", "/auth/register", `{"username":"reader","email":"reader@example.com","password":"long-password-123"}`, "")
	if reg.Code != 201 {
		t.Fatalf("register: %d", reg.Code)
	}
	var user User
	_ = json.Unmarshal(reg.Body.Bytes(), &user)
	if strings.Contains(reg.Body.String(), "long-password-123") || strings.Contains(reg.Body.String(), "$2a$") {
		t.Fatal("password leaked")
	}
	pub := call("GET", "/users/"+user.ID, "", "")
	if pub.Code != 200 || strings.Contains(pub.Body.String(), "email") {
		t.Fatalf("public profile: %d %s", pub.Code, pub.Body.String())
	}
	login := call("POST", "/auth/login", `{"email":"reader@example.com","password":"long-password-123"}`, "")
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &tokens)
	upd := call("PATCH", "/users/me", `{"username":"reader2"}`, tokens.AccessToken)
	if upd.Code != 200 || !strings.Contains(upd.Body.String(), "reader2") {
		t.Fatalf("profile update: %d %s", upd.Code, upd.Body.String())
	}
	if got := call("GET", "/users/"+user.ID, "", ""); got.Code != 200 || !strings.Contains(got.Body.String(), "reader2") {
		t.Fatalf("updated public profile: %d", got.Code)
	}
	if got := call("GET", "/users/no-such-user", "", ""); got.Code != 404 {
		t.Fatalf("missing user: %d", got.Code)
	}
	if got := call("GET", "/health/live", "", ""); got.Code != 200 {
		t.Fatalf("liveness: %d", got.Code)
	}
	if got := call("POST", "/auth/refresh", `{}`, ""); got.Code != 400 {
		t.Fatalf("missing refresh: %d", got.Code)
	}
	if got := call("POST", "/auth/logout", `{}`, tokens.AccessToken); got.Code != 400 {
		t.Fatalf("missing logout token: %d", got.Code)
	}
	if got := call("POST", "/auth/logout", `{"refresh_token":"wrong"}`, tokens.AccessToken); got.Code != 401 {
		t.Fatalf("wrong logout token: %d", got.Code)
	}
	if got := call("PATCH", "/users/me", `{"username":""}`, tokens.AccessToken); got.Code != 400 {
		t.Fatalf("empty username: %d", got.Code)
	}
	if got := call("POST", "/auth/register", `{"username":"another","email":"another@example.com","password":"`+strings.Repeat("x", 73)+`"}`, ""); got.Code != 400 {
		t.Fatalf("long password: %d", got.Code)
	}
	second := call("POST", "/auth/register", `{"username":"second","email":"second@example.com","password":"long-password-123"}`, "")
	if second.Code != 201 {
		t.Fatalf("second register: %d", second.Code)
	}
	if got := call("PATCH", "/users/me", `{"username":"second"}`, tokens.AccessToken); got.Code != 409 {
		t.Fatalf("duplicate username: %d", got.Code)
	}
}
