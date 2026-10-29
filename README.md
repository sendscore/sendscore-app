# sendscore-app

The hosted SendScore app: test addresses, the SMTP receiver, reports, uploads, and the JSON API the MCP tools call. It runs the engine from [sendscore/sendscore](https://github.com/sendscore/sendscore).

## Stack

Go (one binary serving HTTP and SMTP), `html/template`, SQLite (modernc), hand-written CSS with no build, and a CSP with no inline script or style. Modelled on preflightsh-app. Billing will be Creem, ported from Scratchpad.

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

## API

- `POST /api/v1/test-addresses` returns `address`, `token`, `expires_at`, `wait_url`, and `page_url`.
- `GET /api/v1/test-addresses/{token}/wait?timeout=30` long-polls (at most 60 seconds) and returns `{"status": "received", "report_id", "verdict"}` or `{"status": "not_received"}`.
- `GET /api/v1/reports/{id}` returns the verdict JSON.

Addresses accept mail for 24 hours; reports are kept for 7 days.

## Not built yet

Accounts, API keys and rate limits, Creem billing, monitored publications, the heartbeat, alerts (SES), the MCP server, STARTTLS on the receiver, and deploy scripts. Nothing is deployed.

## Develop

```sh
go vet ./... && go test ./...
```

No em or en dashes anywhere. Commits: short one-line messages, no attribution lines.
