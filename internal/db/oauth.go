package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Lifetimes of OAuth codes and tokens.
const (
	OAuthCodeTTL    = 10 * time.Minute
	OAuthAccessTTL  = time.Hour
	OAuthRefreshTTL = 30 * 24 * time.Hour
)

// Prefixes of OAuth tokens, distinct from API tokens.
const (
	OAuthAccessPrefix  = "ss_oat_"
	OAuthRefreshPrefix = "ss_ort_"
)

// MaxOAuthClients bounds the registrations kept. Past it, the oldest
// clients that never got a token are deleted.
const MaxOAuthClients = 2000

// ErrInvalidGrant is a code or refresh token that is unknown, expired, used,
// or bound to another client or redirect URI.
var ErrInvalidGrant = errors.New("invalid grant")

// OAuthClient is a registered MCP client.
type OAuthClient struct {
	ID           string
	Name         string
	RedirectURIs []string
	CreatedAt    time.Time
}

// OAuthCode is what an authorization code was issued for.
type OAuthCode struct {
	ClientID      string
	UserID        string
	RedirectURI   string
	CodeChallenge string
}

// OAuthTokens is a new access and refresh token pair.
type OAuthTokens struct {
	Access, Refresh string
	ExpiresIn       time.Duration
}

// ConnectedApp is a client holding live tokens for a user.
type ConnectedApp struct {
	ClientID string
	Name     string
	Since    time.Time
}

// CreateOAuthClient registers a client.
func (s *Store) CreateOAuthClient(ctx context.Context, name string, redirects []string) (OAuthClient, error) {
	c := OAuthClient{ID: "cli_" + NewToken(10), Name: name, RedirectURIs: redirects, CreatedAt: s.Now().UTC().Truncate(time.Second)}
	uris, _ := json.Marshal(redirects)
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO oauth_clients (id, name, redirect_uris, created_at) VALUES (?, ?, ?, ?)`,
		c.ID, name, string(uris), c.CreatedAt.Unix()); err != nil {
		return c, err
	}
	// Keep the table bounded: drop the oldest registrations nobody connected.
	_, err := s.DB.ExecContext(ctx, `DELETE FROM oauth_clients WHERE id IN (
		SELECT id FROM oauth_clients c WHERE NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id = c.id)
		ORDER BY created_at ASC LIMIT max(0, (SELECT COUNT(*) FROM oauth_clients) - ?))`, MaxOAuthClients)
	return c, err
}

// OAuthClientByID returns a registered client.
func (s *Store) OAuthClientByID(ctx context.Context, id string) (OAuthClient, error) {
	var c OAuthClient
	var uris string
	var created int64
	err := s.DB.QueryRowContext(ctx, `SELECT id, name, redirect_uris, created_at FROM oauth_clients WHERE id = ?`, id).Scan(&c.ID, &c.Name, &uris, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.CreatedAt = time.Unix(created, 0).UTC()
	return c, json.Unmarshal([]byte(uris), &c.RedirectURIs)
}

// CreateOAuthCode issues a single-use authorization code.
func (s *Store) CreateOAuthCode(ctx context.Context, c OAuthCode) (string, error) {
	code := NewToken(32)
	now := s.Now()
	_, err := s.DB.ExecContext(ctx, `INSERT INTO oauth_codes
		(selector, token_hash, client_id, user_id, redirect_uri, code_challenge, family, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		selector(code), HashToken(code), c.ClientID, c.UserID, c.RedirectURI, c.CodeChallenge, "fam_"+NewToken(10), now.Unix(), now.Add(OAuthCodeTTL).Unix())
	return code, err
}

// ExchangeOAuthCode uses up a code and issues the first token pair of its
// grant. check is called with what the code was issued for and must return
// nil for the exchange to go ahead (the caller compares the client, the
// redirect URI, and the PKCE verifier). A code presented a second time
// revokes every token it led to.
func (s *Store) ExchangeOAuthCode(ctx context.Context, code string, check func(OAuthCode) error) (OAuthTokens, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return OAuthTokens{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after commit
	now := s.Now()
	hash, err := match(ctx, tx, `SELECT token_hash, token_hash FROM oauth_codes WHERE selector = ?`, code)
	if errors.Is(err, ErrNotFound) {
		return OAuthTokens{}, ErrInvalidGrant
	}
	if err != nil {
		return OAuthTokens{}, err
	}
	var c OAuthCode
	var family string
	var expires, used int64
	if err := tx.QueryRowContext(ctx, `SELECT client_id, user_id, redirect_uri, code_challenge, family, expires_at, used_at FROM oauth_codes WHERE token_hash = ?`, hash).
		Scan(&c.ClientID, &c.UserID, &c.RedirectURI, &c.CodeChallenge, &family, &expires, &used); err != nil {
		return OAuthTokens{}, err
	}
	if used != 0 {
		if err := revokeFamily(ctx, tx, family, now); err != nil {
			return OAuthTokens{}, err
		}
		return OAuthTokens{}, errors.Join(ErrInvalidGrant, tx.Commit())
	}
	if expires <= now.Unix() {
		return OAuthTokens{}, ErrInvalidGrant
	}
	if err := check(c); err != nil {
		return OAuthTokens{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_codes SET used_at = ? WHERE token_hash = ?`, now.Unix(), hash); err != nil {
		return OAuthTokens{}, err
	}
	t, err := issueTokens(ctx, tx, c.ClientID, c.UserID, family, now)
	if err != nil {
		return OAuthTokens{}, err
	}
	return t, tx.Commit()
}

// RefreshOAuth rotates a refresh token for clientID: the old one is used up
// and a new pair is issued in the same family. A refresh token presented
// again after use revokes the family, since one of the two parties holding
// it is not the client.
func (s *Store) RefreshOAuth(ctx context.Context, refresh, clientID string) (OAuthTokens, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return OAuthTokens{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after commit
	now := s.Now()
	hash, err := match(ctx, tx, `SELECT token_hash, token_hash FROM oauth_tokens WHERE selector = ? AND kind = 'refresh'`, refresh)
	if errors.Is(err, ErrNotFound) {
		return OAuthTokens{}, ErrInvalidGrant
	}
	if err != nil {
		return OAuthTokens{}, err
	}
	var client, user, family string
	var expires, used, revoked int64
	if err := tx.QueryRowContext(ctx, `SELECT client_id, user_id, family, expires_at, used_at, revoked_at FROM oauth_tokens WHERE token_hash = ?`, hash).
		Scan(&client, &user, &family, &expires, &used, &revoked); err != nil {
		return OAuthTokens{}, err
	}
	if client != clientID {
		return OAuthTokens{}, ErrInvalidGrant
	}
	if used != 0 && revoked == 0 {
		if err := revokeFamily(ctx, tx, family, now); err != nil {
			return OAuthTokens{}, err
		}
		return OAuthTokens{}, errors.Join(ErrInvalidGrant, tx.Commit())
	}
	if revoked != 0 || expires <= now.Unix() {
		return OAuthTokens{}, ErrInvalidGrant
	}
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_tokens SET used_at = ? WHERE token_hash = ?`, now.Unix(), hash); err != nil {
		return OAuthTokens{}, err
	}
	t, err := issueTokens(ctx, tx, client, user, family, now)
	if err != nil {
		return OAuthTokens{}, err
	}
	return t, tx.Commit()
}

func issueTokens(ctx context.Context, tx *sql.Tx, client, user, family string, now time.Time) (OAuthTokens, error) {
	t := OAuthTokens{Access: OAuthAccessPrefix + NewToken(32), Refresh: OAuthRefreshPrefix + NewToken(32), ExpiresIn: OAuthAccessTTL}
	for _, row := range []struct {
		token, kind string
		ttl         time.Duration
	}{{t.Access, "access", OAuthAccessTTL}, {t.Refresh, "refresh", OAuthRefreshTTL}} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_tokens (selector, token_hash, kind, client_id, user_id, family, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, selector(row.token), HashToken(row.token), row.kind, client, user, family, now.Unix(), now.Add(row.ttl).Unix()); err != nil {
			return t, err
		}
	}
	return t, nil
}

func revokeFamily(ctx context.Context, tx *sql.Tx, family string, now time.Time) error {
	_, err := tx.ExecContext(ctx, `UPDATE oauth_tokens SET revoked_at = ? WHERE family = ? AND revoked_at = 0`, now.Unix(), family)
	return err
}

// UserByOAuthToken returns the user an unexpired, unrevoked access token
// was issued to.
func (s *Store) UserByOAuthToken(ctx context.Context, token string) (User, error) {
	hash, err := match(ctx, s.DB, `SELECT token_hash, token_hash FROM oauth_tokens
		WHERE selector = ? AND kind = 'access' AND revoked_at = 0 AND expires_at > ?`, token, s.Now().Unix())
	if err != nil {
		return User{}, err
	}
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT u.id, u.email, u.plan, u.created_at FROM users u
		JOIN oauth_tokens t ON t.user_id = u.id WHERE t.token_hash = ?`, hash))
}

// ConnectedApps lists the clients holding a live refresh or access token
// for the user, oldest connection first.
func (s *Store) ConnectedApps(ctx context.Context, userID string) ([]ConnectedApp, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT c.id, c.name, MIN(t.created_at) FROM oauth_tokens t JOIN oauth_clients c ON c.id = t.client_id
		WHERE t.user_id = ? AND t.revoked_at = 0 AND t.used_at = 0 AND t.expires_at > ?
		GROUP BY c.id, c.name ORDER BY MIN(t.created_at)`, userID, s.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectedApp
	for rows.Next() {
		var a ConnectedApp
		var since int64
		if err := rows.Scan(&a.ClientID, &a.Name, &since); err != nil {
			return nil, err
		}
		a.Since = time.Unix(since, 0).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

// DisconnectApp revokes every token and unused code the client holds for
// the user.
func (s *Store) DisconnectApp(ctx context.Context, userID, clientID string) error {
	now := s.Now().Unix()
	if _, err := s.DB.ExecContext(ctx, `UPDATE oauth_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ? AND revoked_at = 0`, now, userID, clientID); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE oauth_codes SET used_at = ? WHERE user_id = ? AND client_id = ? AND used_at = 0`, now, userID, clientID)
	return err
}
