package repository

import (
	"context"
	"database/sql"
	"errors"
	"storybit/auth-service/services"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct{ db *sql.DB }

func OpenPostgres(ctx context.Context, dsn string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &PostgresStore{db: db}, nil
}
func (s *PostgresStore) Close() error                   { return s.db.Close() }
func (s *PostgresStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }
func conflict(err error) error {
	var e *pgconn.PgError
	if errors.As(err, &e) && e.Code == "23505" {
		return services.ErrConflict
	}
	return err
}
func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return services.ErrNotFound
	}
	return err
}
func (s *PostgresStore) CreateUser(ctx context.Context, u services.User) (services.User, error) {
	u.ID = uuid.NewString()
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth.users(id,username,email,password_hash) VALUES($1,$2,$3,$4)`, u.ID, u.Username, u.Email, u.PasswordHash)
	return u, conflict(err)
}
func (s *PostgresStore) UserByEmail(ctx context.Context, email string) (services.User, error) {
	var u services.User
	err := s.db.QueryRowContext(ctx, `SELECT id::text,username,email,password_hash FROM auth.users WHERE lower(email)=lower($1)`, email).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash)
	return u, notFound(err)
}
func (s *PostgresStore) UserByID(ctx context.Context, id string) (services.User, error) {
	var u services.User
	err := s.db.QueryRowContext(ctx, `SELECT id::text,username,email,password_hash FROM auth.users WHERE id=$1`, id).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash)
	return u, notFound(err)
}
func (s *PostgresStore) UpdateUsername(ctx context.Context, id, name string) (services.User, error) {
	var u services.User
	err := s.db.QueryRowContext(ctx, `UPDATE auth.users SET username=$2 WHERE id=$1 RETURNING id::text,username,email,password_hash`, id, name).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash)
	return u, notFound(conflict(err))
}
func (s *PostgresStore) SaveSession(ctx context.Context, id, hash string, expiry time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth.refresh_sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, uuid.NewString(), id, hash, expiry)
	return err
}
func (s *PostgresStore) RotateSession(ctx context.Context, oldHash, newHash string, expiry time.Time) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRowContext(ctx, `UPDATE auth.refresh_sessions SET revoked_at=now() WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now() RETURNING user_id::text`, oldHash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", services.ErrInvalidSession
	}
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO auth.refresh_sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, uuid.NewString(), id, newHash, expiry)
	if err != nil {
		return "", err
	}
	return id, tx.Commit()
}
func (s *PostgresStore) RevokeSession(ctx context.Context, hash, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE auth.refresh_sessions SET revoked_at=now() WHERE token_hash=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()`, hash, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return services.ErrInvalidSession
	}
	return nil
}
