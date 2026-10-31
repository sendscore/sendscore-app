-- Test addresses. A message sent to t-<token>@<mail domain> is checked and
-- stored against the address. Addresses stop accepting mail at expires_at.
CREATE TABLE IF NOT EXISTS addresses (
	token       TEXT PRIMARY KEY,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL
);

-- One received (or uploaded) message and its verdict. New rows keep the
-- original message in message_raw and leave raw empty, since SQLite walks a
-- large raw to reach the verdict after it.
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

-- The original message of a report, for the raw and message views. Kept for
-- SENDSCORE_RAW_DAYS at most, then dropped while the verdict stays.
CREATE TABLE IF NOT EXISTS message_raw (
	id   TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
	raw  BLOB NOT NULL
);

-- Accounts. Sign-in is by emailed link, so there are no passwords. plan is
-- "pro" only for an account the operator granted Pro (SENDSCORE_PRO_EMAILS),
-- and "free" otherwise; a paid plan lives in subscriptions, and the plan in
-- effect is either one (see planExpr in billing.go).
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

-- OAuth for the MCP connector. Clients register themselves (RFC 7591) and
-- are public: no secret, with PKCE doing the work. redirect_uris is a JSON
-- array.
CREATE TABLE IF NOT EXISTS oauth_clients (
	id             TEXT PRIMARY KEY,
	name           TEXT NOT NULL,
	redirect_uris  TEXT NOT NULL,
	created_at     INTEGER NOT NULL
);

-- Single-use authorization codes, bound to the client, the redirect URI,
-- the user, and the PKCE challenge. family is the grant the code starts, so
-- a code used twice revokes every token it led to.
CREATE TABLE IF NOT EXISTS oauth_codes (
	selector        TEXT NOT NULL,
	token_hash      TEXT PRIMARY KEY,
	client_id       TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	redirect_uri    TEXT NOT NULL,
	code_challenge  TEXT NOT NULL,
	family          TEXT NOT NULL,
	created_at      INTEGER NOT NULL,
	expires_at      INTEGER NOT NULL,
	used_at         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS oauth_codes_selector ON oauth_codes(selector);

-- Access and refresh tokens. A refresh token is used once: using it marks it
-- used and issues a new pair in the same family, and presenting a used one
-- again revokes the whole family.
CREATE TABLE IF NOT EXISTS oauth_tokens (
	selector     TEXT NOT NULL,
	token_hash   TEXT PRIMARY KEY,
	kind         TEXT NOT NULL,            -- access or refresh
	client_id    TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	family       TEXT NOT NULL,
	created_at   INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	used_at      INTEGER NOT NULL DEFAULT 0,
	revoked_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS oauth_tokens_selector ON oauth_tokens(selector);
CREATE INDEX IF NOT EXISTS oauth_tokens_user ON oauth_tokens(user_id, client_id);
CREATE INDEX IF NOT EXISTS oauth_tokens_family ON oauth_tokens(family);

-- Browsers that have signed in to an address, so their sign-in requests get
-- their own allowance and a stranger cannot lock the owner out.
CREATE TABLE IF NOT EXISTS known_browsers (
	token_hash  TEXT NOT NULL,
	email       TEXT NOT NULL,
	expires_at  INTEGER NOT NULL,
	PRIMARY KEY (token_hash, email)
);

-- Monitored newsletters. Mail to m-<token>@<mail domain> is checked and
-- stored against the publication, and compared with its last issue. The
-- address never expires. days is a bit set of weekdays (bit 0 is Sunday) and
-- at a local time HH:MM in time_zone; days 0 means no schedule. watch_since
-- is when the schedule last changed or alerts were last turned back on, so a
-- slot from before then is never reported as missed.
CREATE TABLE IF NOT EXISTS publications (
	id             TEXT PRIMARY KEY,
	user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	name           TEXT NOT NULL,
	token          TEXT NOT NULL UNIQUE,
	days           INTEGER NOT NULL DEFAULT 0,
	at             TEXT NOT NULL DEFAULT '',
	time_zone      TEXT NOT NULL DEFAULT 'UTC',
	grace_minutes  INTEGER NOT NULL DEFAULT 30,
	alert_email    TEXT NOT NULL,
	paused         INTEGER NOT NULL DEFAULT 0,
	watch_since    INTEGER NOT NULL,
	created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS publications_user ON publications(user_id, created_at);

-- Alerts, written before they are sent so a restart never sends one twice.
-- key is what the alert is about (report:<id> or slot:<unix>), and the
-- unique index makes each one once only. status is pending, sending, sent,
-- failed, capped (over a cap, never sent), or stopped (the recipient opted out).
CREATE TABLE IF NOT EXISTS alerts (
	id              TEXT PRIMARY KEY,
	publication_id  TEXT NOT NULL REFERENCES publications(id) ON DELETE CASCADE,
	kind            TEXT NOT NULL,            -- worse, missed, or duplicate
	key             TEXT NOT NULL,
	report_id       TEXT NOT NULL DEFAULT '',
	to_addr         TEXT NOT NULL,
	subject         TEXT NOT NULL,
	text_body       TEXT NOT NULL,
	html_body       TEXT NOT NULL,
	status          TEXT NOT NULL,
	attempts        INTEGER NOT NULL DEFAULT 0,
	error           TEXT NOT NULL DEFAULT '',
	created_at      INTEGER NOT NULL,
	claimed_at      INTEGER NOT NULL DEFAULT 0,
	sent_at         INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS alerts_once ON alerts(publication_id, kind, key);
CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status);

-- Everyone alerts have been addressed to, by the hash of the address, so an
-- opt-out holds across accounts and outlives them without keeping the
-- address. token goes in each alert's opt-out link. stopped_at is 0 unless the
-- recipient opted out.
CREATE TABLE IF NOT EXISTS alert_recipients (
	token       TEXT PRIMARY KEY,
	email_hash  TEXT NOT NULL UNIQUE,
	created_at  INTEGER NOT NULL,
	stopped_at  INTEGER NOT NULL DEFAULT 0
);

-- The Creem subscription behind an account's paid plan, kept up to date by
-- Creem's webhooks and by nothing else. status is empty until an event says
-- one, then active, past_due, paused, or cancelled. period_end is Unix
-- seconds (0 for none). event_at is the Creem time, in milliseconds, of the
-- newest event whose status was applied, so a late delivery of an older one
-- is recorded and ignored; NULL orders nothing.
CREATE TABLE IF NOT EXISTS subscriptions (
	user_id          TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
	customer_id      TEXT NOT NULL DEFAULT '',
	subscription_id  TEXT NOT NULL DEFAULT '',
	status           TEXT NOT NULL DEFAULT '',
	product_id       TEXT NOT NULL DEFAULT '',
	period_end       INTEGER NOT NULL DEFAULT 0,
	event_at         INTEGER,
	updated_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS subscriptions_subscription ON subscriptions(subscription_id);
CREATE INDEX IF NOT EXISTS subscriptions_customer ON subscriptions(customer_id);

-- Every Creem webhook event, applied or not. The id is the primary key, so a
-- retry of an event already recorded is never applied twice. user_id is NULL
-- for an event that names no account here, which is the operator's queue.
-- event_at is Creem's time in milliseconds, or NULL; body is the first 20000
-- bytes of what Creem sent.
CREATE TABLE IF NOT EXISTS creem_events (
	id           TEXT PRIMARY KEY,
	kind         TEXT NOT NULL,
	user_id      TEXT,
	received_at  INTEGER NOT NULL,
	event_at     INTEGER,
	body         TEXT NOT NULL
);
