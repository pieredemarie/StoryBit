package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var ErrConflict = errors.New("conflict")
var ErrNotFound = errors.New("not found")
var ErrInvalidSession = errors.New("invalid session")
var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidInput = errors.New("invalid input")
var ErrInvalidToken = errors.New("invalid token")

const accessTTL = 15 * time.Minute
const refreshTTL = 30 * 24 * time.Hour

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email,omitempty"`
	PasswordHash string `json:"-"`
}
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}
type Repository interface {
	Ping(context.Context) error
	CreateUser(context.Context, User) (User, error)
	UserByEmail(context.Context, string) (User, error)
	UserByID(context.Context, string) (User, error)
	UpdateUsername(context.Context, string, string) (User, error)
	SaveSession(context.Context, string, string, time.Time) error
	RotateSession(context.Context, string, string, time.Time) (string, error)
	RevokeSession(context.Context, string, string) error
}
type AuthService struct {
	repo   Repository
	secret []byte
}

func NewAuthService(repo Repository, secret []byte) *AuthService {
	return &AuthService{repo: repo, secret: append([]byte(nil), secret...)}
}
func (s *AuthService) Ready(ctx context.Context) error { return s.repo.Ping(ctx) }

func (s *AuthService) Register(ctx context.Context, username, email, password string) (User, error) {
	username = strings.TrimSpace(username)
	email = strings.ToLower(strings.TrimSpace(email))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || utf8.RuneCountInString(username) < 1 || utf8.RuneCountInString(username) > 50 || len(password) < 12 || len([]byte(password)) > 72 {
		return User{}, ErrInvalidInput
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	u, err := s.repo.CreateUser(ctx, User{Username: username, Email: email, PasswordHash: string(hash)})
	if err != nil {
		return User{}, err
	}
	u.PasswordHash = ""
	return u, nil
}
func (s *AuthService) Login(ctx context.Context, email, password string) (Tokens, error) {
	if strings.TrimSpace(email) == "" || password == "" {
		return Tokens{}, ErrInvalidInput
	}
	u, err := s.repo.UserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if errors.Is(err, ErrNotFound) {
		return Tokens{}, ErrInvalidCredentials
	}
	if err != nil {
		return Tokens{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return Tokens{}, ErrInvalidCredentials
	}
	return s.issue(ctx, u.ID)
}
func (s *AuthService) issue(ctx context.Context, id string) (Tokens, error) {
	access, err := s.accessToken(id)
	if err != nil {
		return Tokens{}, err
	}
	refresh, err := randomToken()
	if err != nil {
		return Tokens{}, err
	}
	if err = s.repo.SaveSession(ctx, id, digest(refresh), time.Now().Add(refreshTTL)); err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: int(accessTTL.Seconds())}, nil
}
func (s *AuthService) Refresh(ctx context.Context, old string) (Tokens, error) {
	if old == "" {
		return Tokens{}, ErrInvalidInput
	}
	next, err := randomToken()
	if err != nil {
		return Tokens{}, err
	}
	id, err := s.repo.RotateSession(ctx, digest(old), digest(next), time.Now().Add(refreshTTL))
	if err != nil {
		return Tokens{}, err
	}
	access, err := s.accessToken(id)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, RefreshToken: next, TokenType: "Bearer", ExpiresIn: int(accessTTL.Seconds())}, nil
}
func (s *AuthService) Logout(ctx context.Context, id, refresh string) error {
	if refresh == "" {
		return ErrInvalidInput
	}
	return s.repo.RevokeSession(ctx, digest(refresh), id)
}
func (s *AuthService) Profile(ctx context.Context, id string) (User, error) {
	u, err := s.repo.UserByID(ctx, id)
	u.PasswordHash = ""
	return u, err
}
func (s *AuthService) UpdateProfile(ctx context.Context, id, username string) (User, error) {
	username = strings.TrimSpace(username)
	if utf8.RuneCountInString(username) < 1 || utf8.RuneCountInString(username) > 50 {
		return User{}, ErrInvalidInput
	}
	u, err := s.repo.UpdateUsername(ctx, id, username)
	u.PasswordHash = ""
	return u, err
}
func (s *AuthService) accessToken(id string) (string, error) {
	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{Issuer: "storybit-auth", Subject: id, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(accessTTL))}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}
func (s *AuthService) VerifyAccess(raw string) (string, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return s.secret, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("storybit-auth"), jwt.WithExpirationRequired())
	if err != nil || !token.Valid || claims.Subject == "" {
		return "", ErrInvalidToken
	}
	return claims.Subject, nil
}
func randomToken() (string, error) {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf), err
}
func digest(raw string) string { h := sha256.Sum256([]byte(raw)); return hex.EncodeToString(h[:]) }
