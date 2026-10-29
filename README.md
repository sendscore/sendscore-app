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

1. Open http://127.0.0.1:3014 and press "Get a test address" (or `curl -X POST http://127.0.0.1:3014/api/v1/test-addresses`).
2. Deliver a saved email to it: `go run ./cmd/sendtest -to t-<token>@localhost ../sendscore/testdata/sample.eml`. Any `.eml` works; save one from Gmail with "Show original" then "Download original".
3. The page opens the report on its own. Locally the message comes from 127.0.0.1 without TLS, so SPF, reverse DNS, and TLS reflect that; DKIM and DMARC are checked against real DNS.

Or upload a saved file at http://127.0.0.1:3014/upload.

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
| `SENDSCORE_TLS_CERT`, `SENDSCORE_TLS_KEY` | unset: STARTTLS off. Production must set them (a certificate for the mail domain), or every message fails `auth.tls`. |

## API

- `POST /api/v1/test-addresses` returns `address`, `token`, `expires_at`, `wait_url`, and `page_url`.
- `GET /api/v1/test-addresses/{token}/wait?timeout=30` long-polls (at most 60 seconds) and returns `{"status": "received", "report_id", "verdict"}` or `{"status": "not_received"}`.
- `GET /api/v1/reports/{id}` returns the verdict JSON.

- `/api/mcp` is the remote MCP connector (streamable HTTP) with `get_test_address`, `wait_for_message`, `get_report`, and `compare_to_previous`. The tools live in the engine repository's `mcpserver` package; here they read the database directly.

Addresses accept mail for 24 hours; reports are kept for 7 days.

## Not built yet

Accounts, API keys and rate limits, monitored publications, the heartbeat, alerts (SES), a Docker image and self-hosting docs, Creem billing (hosted only), and deploy scripts. Nothing is deployed.

## Develop

```sh
go vet ./... && go test ./...
```

No em or en dashes anywhere. Commits: short one-line messages, no attribution lines.

## License

AGPL-3.0. The engine and CLI it imports are MIT.
