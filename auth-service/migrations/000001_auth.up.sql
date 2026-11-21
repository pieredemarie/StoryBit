CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE auth.users (
 id UUID PRIMARY KEY,
 username VARCHAR(50) NOT NULL,
 email VARCHAR(255) NOT NULL,
 password_hash TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_ci_unique ON auth.users (lower(email));
CREATE UNIQUE INDEX users_username_ci_unique ON auth.users (lower(username));
CREATE TABLE auth.refresh_sessions (
 id UUID PRIMARY KEY,
 user_id UUID NOT NULL REFERENCES auth.users(id),
 token_hash TEXT NOT NULL UNIQUE,
 expires_at TIMESTAMPTZ NOT NULL,
 revoked_at TIMESTAMPTZ
);
CREATE INDEX refresh_sessions_user_id_idx ON auth.refresh_sessions(user_id);
