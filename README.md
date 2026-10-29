# sendscore-app

The SendScore app: test addresses, the SMTP receiver, reports, uploads, and the JSON API the MCP tools call. It runs the engine from [sendscore/sendscore](https://github.com/sendscore/sendscore).

It is open source (AGPL-3.0) and self-hostable: run it on your own server with your own domain, or use the hosted version at [sendscore.ai](https://sendscore.ai). Self-hosting needs a server that can receive mail on port 25 and a domain whose MX record points at it.

## Stack

Go (one binary serving HTTP and SMTP), `html/template`, SQLite (modernc), hand-written CSS with no build, and a CSP with no inline script or style. Modelled on preflightsh-app. Billing for the hosted version will be Creem, ported from Scratchpad, as an optional module: a self-hosted instance runs without it.

## Run locally

The engine is private until launch, so clone it next to this repository; `go.mod` points at `../sendscore`.

```sh
git clone git@github.com:sendscore/sendscore.git ../sendscore   # once
go run .
```

That serves the web app on http://127.0.0.1:3014 and the SMTP receiver on 127.0.0.1:2525, with test addresses at `@localhost` and the database in `sendscore.db`.

To test the whole loop:

1. Open http://127.0.0.1:3014 and press "Get a test address" (or, with an API token from the account page, `curl -X POST -H "Authorization: Bearer $SENDSCORE_TOKEN" http://127.0.0.1:3014/api/v1/test-addresses`).
2. Deliver a saved email to it: `go run ./cmd/sendtest -to t-<token>@localhost ../sendscore/testdata/sample.eml`. Any `.eml` works; save one from Gmail with "Show original" then "Download original".
3. The page opens the report on its own. Locally the message comes from 127.0.0.1 without TLS, so SPF, reverse DNS, and TLS reflect that; DKIM and DMARC are checked against real DNS.

Or upload a saved file at http://127.0.0.1:3014/upload.

## Accounts

Sign-in is by emailed link, with no passwords. `/signin` takes an email address and sends a link to `/signin/verify` that works once and expires in 15 minutes. Opening the link shows a "Sign in" button, so a mail scanner that follows links cannot use it up; pressing it creates the account on a first sign-in, starts a 30-day session, and opens `/account`. The page after the form always says "Check your email", whether or not the address has an account. Each address and each IP may request 5 links an hour.

Without SES keys the link is written to the app's log instead of emailed. To sign in locally that way, submit the form, then copy the `/signin/verify?t=...` link from the terminal. With the SES keys in `.env.local`, a local run sends real email, and the link points at `SENDSCORE_BASE_URL`.

`/account` shows today's usage and the API tokens. Create a named token there (it is shown once, so copy it then), see each one's prefix (such as `ss_live_abcd`), when it was created, and when it was last used, and revoke it. Sign-in links, sessions, and tokens are stored only as SHA-256 hashes. Every form carries a CSRF token and must come from the site itself (by `Origin` or `Referer`).

Test addresses are limited per UTC day. A free account gets 25 (through the API, MCP, or the site while signed in), and an anonymous visitor gets 5 per IP for "Get a test address" and uploads together. Over the limit, the API answers 429 and the site shows a page saying when it starts again. Every account is on the `free` plan (`users.plan`) until billing lifts the limits.

Settings (environment, or `.env.local`):

| Variable | Default |
| --- | --- |
| `SENDSCORE_ADDR` | `127.0.0.1:3014` |
| `SENDSCORE_SMTP_ADDR` | `127.0.0.1:2525` |
| `SENDSCORE_MAIL_DOMAIN` | `localhost` (production: the domain the MX record points here) |
| `SENDSCORE_BASE_URL` | `http://` plus the web address |
| `SENDSCORE_DB` | `sendscore.db` |
| `SENDSCORE_SPAMHAUS_DQS_KEY` | unset: no Spamhaus lookups. A Spamhaus DQS key, which allows commercial use. The hosted service must use this. |
| `SENDSCORE_SURBL_ZONE` | unset: no SURBL lookups. A SURBL data feed zone, for subscribers. |
| `SENDSCORE_PUBLIC_BLOCKLISTS` | unset. `1` uses the free public Spamhaus and SURBL zones, which are for non-commercial use only (a personal self-hosted instance). |
| `SENDSCORE_CHECK_LINKS` | on. Fetches every link and image in received and uploaded messages, with a client that refuses private and loopback addresses and never fetches unsubscribe, confirm, or preference links. `0` turns it off, and `content.links` and `content.images` are skipped. |
| `SENDSCORE_TLS_CERT`, `SENDSCORE_TLS_KEY` | unset: STARTTLS off. Production must set them (a certificate for the mail domain), or every message fails `auth.tls`. |
| `SENDSCORE_SECURE_COOKIES` | unset. `true` in production (HTTPS): cookies are marked Secure, and the app refuses to start without `SENDSCORE_BASE_URL` and the SES keys, so sign-in links never come from the Host header or land in the log. |
| `SES_ACCESS_KEY_ID`, `SES_SECRET_ACCESS_KEY` | unset: sign-in links are logged, not emailed (development only). |
| `SES_REGION` | `us-east-1` |
| `SENDSCORE_MAIL_FROM` | `SendScore <hello@sendscore.ai>` |
| `SENDSCORE_FREE_DAILY_TESTS` | `25` test addresses per UTC day for a free account |
| `SENDSCORE_ANON_DAILY_TESTS` | `5` test addresses and uploads per UTC day for an anonymous IP |
| `SENDSCORE_TRUST_PROXY` | unset. `1` behind a reverse proxy: the client IP for limits is the last `X-Forwarded-For` entry, the one the proxy added. Leave it unset when the app is reachable directly, or anyone could choose their IP. |

## Connector (OAuth)

To connect Claude or another MCP client, add `https://app.sendscore.ai/api/mcp` as a custom connector (locally, `http://127.0.0.1:3014/api/mcp`). You will be asked to sign in and allow access. Nothing needs pasting, because the client finds the sign-in on its own, as the MCP authorization spec describes (OAuth 2.1 with PKCE).

1. An unauthenticated call to `/api/mcp` gets a 401 with `WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource/api/mcp"` (and `error="invalid_token"` when a token was sent but is no good).
2. `/.well-known/oauth-protected-resource` (and its `/api/mcp` variant) is RFC 9728 metadata naming the app as the authorization server, and `/.well-known/oauth-authorization-server` is RFC 8414 metadata. There is also `/.well-known/mcp/server-card.json`.
3. The client registers itself at `POST /oauth/register` (RFC 7591). Clients are public, so a request for a secret is registered without one, and the reply says `token_endpoint_auth_method` is `none`. A redirect URI must be https, http on 127.0.0.1 or localhost, or a native app's own scheme (such as `cursor://` or `vscode://`, which those editors use), with no fragment or wildcard; unusable ones are dropped, and a list with none left is refused. Each IP may register 20 clients an hour, and the oldest registrations that never connected are deleted past 2,000. A name that claims to be SendScore is not kept.
4. `GET /oauth/authorize` sends a signed-out visitor through email sign-in and back, then shows a consent page naming the client and where it sends you, with Allow and Deny. It checks the client, an exact `redirect_uri`, PKCE with `S256`, and `resource` (RFC 8707), which must be `<base>/api/mcp` when given, and passes `state` through. Allow returns a single-use code that expires in 10 minutes, bound to the client, the redirect URI, the user, and the PKCE challenge, along with `iss` (RFC 9207).
5. `POST /oauth/token` swaps the code and its `code_verifier` for an access token (an hour) and a refresh token (30 days). A refresh token is used once. Each refresh returns a new pair, and presenting an old one again revokes every token of that connection. A code used twice does the same.

OAuth tokens (`ss_oat_...`) work only on `/api/mcp`, where an API token works too. They act for the user who allowed them, so ownership and the daily allowance apply as for API tokens. `/account` lists connected apps with a Disconnect button that revokes their tokens. All codes and tokens are stored only as SHA-256 hashes.

To try it locally, run `npx @modelcontextprotocol/inspector`, choose Streamable HTTP with `http://127.0.0.1:3014/api/mcp`, and use its OAuth flow; the sign-in link is in the app's log when SES is off.

## API

Every `/api/v1/` route and `/api/mcp` take an API token from the account page in the `Authorization` header:

```sh
curl -H "Authorization: Bearer ss_live_..." -X POST https://sendscore.ai/api/v1/test-addresses
```

A missing, unknown, or revoked token gets a 401 (`{"error": ...}` on `/api/v1/`, and a plain 401 with `WWW-Authenticate: Bearer` on `/api/mcp`). Addresses made with a token belong to its account, and the wait, report, and MCP tools answer only for that account's addresses, with a 404 for anyone else's. The report page `/r/{id}`, its `/r/{id}/json`, and the address page `/t/{token}` stay viewable by their unguessable links. `sendscore mcp` sends the token from `SENDSCORE_TOKEN`.

- `POST /api/v1/test-addresses` returns `address`, `token`, `expires_at`, `wait_url`, and `page_url`.
- `GET /api/v1/test-addresses/{token}/wait?timeout=30` long-polls (at most 50 seconds, below common proxy timeouts) and returns `{"status": "received", "report_id", "report_url", "verdict"}` or `{"status": "not_received"}`. It returns the newest message at the address, even one that arrived before the call. To check a second send to the same address, add `&after=<report_id>` with the earlier report, and only a newer message counts; an `after` that is not a report from this address is a 400. The page `/t/{token}?after=<report_id>` waits the same way.
- `GET /api/v1/reports/{id}` returns the verdict JSON.

- `/api/mcp` is the remote MCP connector (streamable HTTP, with the token as above) with `get_test_address`, `wait_for_message` (with an optional `after_report_id`, as `after` above), `get_report`, and `compare_to_previous`. The tools live in the engine repository's `mcpserver` package; here they read the database directly.

Addresses accept mail for 24 hours; reports are kept for 7 days. A message is checked once per transaction and for one test address: a repeated `RCPT` for the same address is accepted once, and a second address gets a 452, so the sender delivers it separately. A `MAIL FROM` with control characters or angle brackets gets a 501. Uploads and messages are limited to 25 MB, and a larger upload is refused, never cut short.

Upload reports say they came from an upload, and mark the sending IP and envelope sender as supplied by the uploader, since SendScore did not see the delivery.

On shutdown (SIGTERM), open waits answer `not_received` at once, and uploads and SMTP sessions get up to a minute to finish their checks and save; anything still open after that is dropped and retried by the sender. Give the process manager a stop timeout of more than a minute (systemd's default is 90 seconds).

## Not built yet

Monitored publications, the heartbeat, alerts (SES), a Docker image and self-hosting docs, Creem billing (hosted only), and deploy scripts. Nothing is deployed.

## Develop

```sh
go vet ./... && go test ./...
```

No em or en dashes anywhere. Commits: short one-line messages, no attribution lines.

## License

AGPL-3.0. The engine and CLI it imports are MIT.
