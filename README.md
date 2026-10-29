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
| `SENDSCORE_CHECK_LINKS` | on. Fetches every link and image in received and uploaded messages, with a client that refuses private and loopback addresses and never fetches unsubscribe, confirm, or preference links. `0` turns it off, and `content.links` and `content.images` are skipped. |
| `SENDSCORE_TLS_CERT`, `SENDSCORE_TLS_KEY` | unset: STARTTLS off. Production must set them (a certificate for the mail domain), or every message fails `auth.tls`. |

## API

- `POST /api/v1/test-addresses` returns `address`, `token`, `expires_at`, `wait_url`, and `page_url`.
- `GET /api/v1/test-addresses/{token}/wait?timeout=30` long-polls (at most 50 seconds, below common proxy timeouts) and returns `{"status": "received", "report_id", "report_url", "verdict"}` or `{"status": "not_received"}`. It returns the newest message at the address, even one that arrived before the call. To check a second send to the same address, add `&after=<report_id>` with the earlier report, and only a newer message counts; an `after` that is not a report from this address is a 400. The page `/t/{token}?after=<report_id>` waits the same way.
- `GET /api/v1/reports/{id}` returns the verdict JSON.

- `/api/mcp` is the remote MCP connector (streamable HTTP) with `get_test_address`, `wait_for_message` (with an optional `after_report_id`, as `after` above), `get_report`, and `compare_to_previous`. The tools live in the engine repository's `mcpserver` package; here they read the database directly.

Addresses accept mail for 24 hours; reports are kept for 7 days. A message is checked once per transaction and for one test address: a repeated `RCPT` for the same address is accepted once, and a second address gets a 452, so the sender delivers it separately. A `MAIL FROM` with control characters or angle brackets gets a 501. Uploads and messages are limited to 25 MB, and a larger upload is refused, never cut short.

Upload reports say they came from an upload, and mark the sending IP and envelope sender as supplied by the uploader, since SendScore did not see the delivery.

On shutdown (SIGTERM), open waits answer `not_received` at once, and uploads and SMTP sessions get up to a minute to finish their checks and save; anything still open after that is dropped and retried by the sender. Give the process manager a stop timeout of more than a minute (systemd's default is 90 seconds).

## Not built yet

Accounts, API keys and rate limits, monitored publications, the heartbeat, alerts (SES), a Docker image and self-hosting docs, Creem billing (hosted only), and deploy scripts. Nothing is deployed.

## Develop

```sh
go vet ./... && go test ./...
```

No em or en dashes anywhere. Commits: short one-line messages, no attribution lines.

## License

AGPL-3.0. The engine and CLI it imports are MIT.
