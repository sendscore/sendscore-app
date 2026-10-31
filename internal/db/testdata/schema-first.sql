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
