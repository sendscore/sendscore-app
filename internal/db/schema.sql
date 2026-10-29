-- Test addresses. A message sent to t-<token>@<mail domain> is checked and
-- stored against the address. Addresses stop accepting mail at expires_at.
CREATE TABLE IF NOT EXISTS addresses (
	token       TEXT PRIMARY KEY,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL
);

-- One received (or uploaded) message and its verdict. raw is kept so a
-- report can be re-run when the engine changes; it is deleted with the row.
CREATE TABLE IF NOT EXISTS messages (
	id           TEXT PRIMARY KEY,
	token        TEXT REFERENCES addresses(token) ON DELETE CASCADE,
	source       TEXT NOT NULL,            -- smtp or upload
	received_at  INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	remote_ip    TEXT NOT NULL DEFAULT '',
	helo         TEXT NOT NULL DEFAULT '',
	mail_from    TEXT NOT NULL DEFAULT '',
	rcpt_to      TEXT NOT NULL DEFAULT '',
	tls          INTEGER,                  -- NULL when unknown
	raw          BLOB NOT NULL,
	verdict      TEXT NOT NULL             -- verdict JSON
);
CREATE INDEX IF NOT EXISTS messages_token ON messages(token, received_at);
CREATE INDEX IF NOT EXISTS messages_expires ON messages(expires_at);

-- Accounts. Sign-in is by emailed link, so there are no passwords. plan is
-- "free" until billing lifts the limits.
CREATE TABLE IF NOT EXISTS users (
	id          TEXT PRIMARY KEY,
	email       TEXT NOT NULL UNIQUE,
	plan        TEXT NOT NULL DEFAULT 'free',
	created_at  INTEGER NOT NULL
);

-- Secrets (sign-in links, sessions, and API tokens) are stored only as the
-- SHA-256 of the whole token. selector is the token's first 12 characters,
-- used to find the row before the hashes are compared in constant time; for
-- an API token it is also the prefix shown on the account page.

-- Single-use sign-in links.
CREATE TABLE IF NOT EXISTS login_tokens (
	selector    TEXT NOT NULL,
	token_hash  TEXT PRIMARY KEY,
	email       TEXT NOT NULL,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	used_at     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS login_tokens_selector ON login_tokens(selector);

CREATE TABLE IF NOT EXISTS sessions (
	selector    TEXT NOT NULL,
	token_hash  TEXT PRIMARY KEY,
	user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_selector ON sessions(selector);

CREATE TABLE IF NOT EXISTS api_tokens (
	id            TEXT PRIMARY KEY,
	user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	name          TEXT NOT NULL,
	selector      TEXT NOT NULL,
	token_hash    TEXT NOT NULL UNIQUE,
	created_at    INTEGER NOT NULL,
	last_used_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS api_tokens_selector ON api_tokens(selector);
CREATE INDEX IF NOT EXISTS api_tokens_user ON api_tokens(user_id, created_at);

-- Usage counters for limits: name is what is counted (such as
-- tests:user:<id> or signin:ip:<ip>) and bucket the UTC day or hour.
CREATE TABLE IF NOT EXISTS counters (
	name        TEXT NOT NULL,
	bucket      TEXT NOT NULL,
	count       INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	PRIMARY KEY (name, bucket)
);
CREATE INDEX IF NOT EXISTS counters_expires ON counters(expires_at);
