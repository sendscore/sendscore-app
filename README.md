# sendscore-app

The SendScore app: test addresses, newsletter monitoring with alerts, the SMTP receiver, reports, uploads, and the JSON API the MCP tools call. It runs the engine from [sendscore/sendscore](https://github.com/sendscore/sendscore).

It is open source (AGPL-3.0), and you run it yourself on your own server with your own domain. It needs a server that can receive mail on port 25 and a domain whose MX record points at it. Many cloud hosts block port 25 until you ask, so check yours first.

There is no hosted version right now. If you would use one, [open an issue](https://github.com/sendscore/sendscore/issues) and say so. To check saved messages without running a server, use the [CLI](https://github.com/sendscore/sendscore).

## Stack

Go (one binary serving HTTP and SMTP), `html/template`, SQLite (modernc), hand-written CSS with no build, and a CSP with no inline script or style. Billing through Creem is optional and off by default (see Billing below).

## Run locally

Sign-ups are closed by default, so to sign in, first put `SENDSCORE_PRO_EMAILS=you@example.com` in `.env.local`.

```sh
go run .
```

That serves the web app on http://127.0.0.1:3014 and the SMTP receiver on 127.0.0.1:2525, with test addresses at `@localhost` and the database in `sendscore.db`.

To test the whole loop:

1. Open http://127.0.0.1:3014 and press "Get a test address" (or, with an API token from the account page, `curl -X POST -H "Authorization: Bearer $SENDSCORE_TOKEN" http://127.0.0.1:3014/api/v1/test-addresses`).
2. Deliver a saved email to it: `go run ./cmd/sendtest -to t-<token>@localhost testdata/sample.eml`. Any `.eml` works; save one from Gmail with "Show original" then "Download original".
3. The page opens the report on its own. Locally the message comes from 127.0.0.1 without TLS, so SPF, reverse DNS, and TLS reflect that; DKIM and DMARC are checked against real DNS.

Or upload a saved file at http://127.0.0.1:3014/upload.

## Accounts

Sign-in is by emailed link, with no passwords. `/signin` takes an email address and sends a link to `/signin/verify` that works once and expires in 15 minutes. Opening the link shows the address it signs in as and a "Sign in" button, so a mail scanner that follows links cannot use it up, and a link someone else forwarded says whose account it opens. Pressing it creates the account on a first sign-in, starts a 30-day session, and opens `/account`. The page after the form always says "Check your email", whether or not the address has an account.

Sign-in emails are limited per hour: 5 per network (an IPv4 address, or an IPv6 /48), 20 per wider network (an IPv6 /32), 5 per address, and `SENDSCORE_SIGNIN_EMAILS_PER_HOUR` for the whole service. A browser that has signed in to an address before (it keeps a `ss_browser` cookie for a year) has its own 5 an hour for that address and its own share of the service limit, so strangers who use up either cannot lock an owner out of the browsers they already use.

Sign-ups are closed by default when billing is off (`SENDSCORE_SIGNUPS`). Accounts that exist still sign in, and so do the addresses in `SENDSCORE_PRO_EMAILS`, so put your own address there before you first sign in. Anyone else sees the same "Check your email" page and gets an email saying this instance takes no new accounts, so neither the page nor its timing shows who has an account. Only set `SENDSCORE_SIGNUPS=open` with billing off if you mean to give the public Pro limits on your disk and sending account.

Without SES keys the link is written to the app's log instead of emailed. To sign in locally that way, submit the form, then copy the `/signin/verify?t=...` link from the terminal. With the SES keys in `.env.local`, a local run sends real email, and the link points at `SENDSCORE_BASE_URL`.

`/account` shows today's usage and the API tokens. Create a named token there (it is shown once, so copy it then), see each one's prefix (such as `ss_live_abcd`), when it was created, and when it was last used, and revoke it. Sign-in links, sessions, and tokens are stored only as SHA-256 hashes. Every form carries a CSRF token and must come from the site itself by `Origin`, or `Referer` when there is no `Origin`; a post with neither is refused. Both are checked before the body is read. With secure cookies the cookies are named `__Host-ss_session`, `__Host-ss_csrf`, and `__Host-ss_browser`, so no other subdomain can set them, and every response carries `Strict-Transport-Security`.

Test addresses are limited per UTC day. A free account gets 25 (through the API, MCP, or the site while signed in), and an anonymous visitor gets 5 per IP for "Get a test address" and uploads together. Over the limit, the API answers 429 and the site shows a page saying when it starts again. With billing off, which is the default, every account has the Pro limits. That is worked out each time a plan is read and never stored, so turning billing on later puts every account back on its real plan. With billing on, an account is Pro when the operator granted it (the addresses in `SENDSCORE_PRO_EMAILS`, set to `pro` in `users.plan` at startup and whenever they sign in) or when its Creem subscription is in good standing, and free otherwise. No webhook can take Pro away from a granted account. Pro is what allows newsletter monitoring (see below).

Anonymous tests are off by default on a public instance with closed sign-ups (`SENDSCORE_ANON_DAILY_TESTS` is then `0`). Otherwise all anonymous visitors together get `SENDSCORE_ANON_DAILY_TOTAL` tests a UTC day, on top of the limit per IP.

Delete an account from the Account page. SendScore cancels any Creem subscription first and deletes nothing if it cannot. It then deletes the account's test addresses, messages and reports (including the original messages), monitored newsletters with their history and alerts, API tokens, connected apps, and sessions. Creem webhook records are kept as the payment record, without the account or their payload, and opt-outs from alerts are kept, as a hash of the address. Signing in again with the same email starts a new account.

Settings (environment, or `.env.local`):

| Variable | Default |
| --- | --- |
| `SENDSCORE_ADDR` | `127.0.0.1:3014` |
| `SENDSCORE_SMTP_ADDR` | `127.0.0.1:2525` |
| `SENDSCORE_MAIL_DOMAIN` | `localhost`. Required in production (the domain the MX record points here); the app refuses to start without it when cookies are secure. |
| `SENDSCORE_BASE_URL` | `http://` plus the web address. It must be a full URL, and https when cookies are secure. |
| `SENDSCORE_DB` | `sendscore.db`. The app keeps it readable by its owner only, since it holds raw mail. |
| `SENDSCORE_RAW_DAYS` | `30` days the original of a message is kept. Its report stays until the message expires. |
| `SENDSCORE_SPAMHAUS_DQS_KEY` | unset: no Spamhaus lookups. A Spamhaus DQS key, which allows commercial use. Any commercial instance must use this. |
| `SENDSCORE_SURBL_ZONE` | unset: no SURBL lookups. A SURBL data feed zone, for subscribers. |
| `SENDSCORE_PUBLIC_BLOCKLISTS` | off. `true` uses the free public Spamhaus and SURBL zones, which are for non-commercial use only (a personal self-hosted instance). |
| `SENDSCORE_CHECK_LINKS` | on. Fetches every link and image in received and uploaded messages, with a client that refuses private and loopback addresses and never fetches unsubscribe, confirm, or preference links. `false` turns it off, and `content.links` and `content.images` are skipped. |
| `SENDSCORE_TLS_CERT`, `SENDSCORE_TLS_KEY` | unset: STARTTLS off. Production must set them (a certificate for the mail domain), or every message fails `auth.tls`. The files are checked once a minute and reloaded when they change, so a renewal needs no restart. |
| `SENDSCORE_SECURE_COOKIES` | `true` when `SENDSCORE_BASE_URL` is https, otherwise `false`. When true, cookies are Secure and `__Host-` named, responses carry HSTS, and the app refuses to start without an https `SENDSCORE_BASE_URL` and the SES keys, so sign-in links never come from the Host header or land in the log. |
| `SES_ACCESS_KEY_ID`, `SES_SECRET_ACCESS_KEY` | unset: sign-in links are logged, not emailed (development only). With them, the two senders below are required. |
| `SES_REGION` | `us-east-1` |
| `SENDSCORE_MAIL_FROM` | unset. The sender of sign-in links, such as `SendScore <hello@example.com>`, verified in SES. |
| `SENDSCORE_ALERT_FROM` | unset. The sender of alerts and alert confirmations, verified in SES. |
| `SENDSCORE_PRO_EMAILS` | unset. Comma separated addresses whose accounts are Pro whatever billing says, and who may sign up while sign-ups are closed. |
| `SENDSCORE_SIGNUPS` | `closed` with billing off, `open` with billing on. `open` lets anyone make an account. |
| `CREEM_API_KEY` | unset: billing off, the default, which gives every account the Pro limits. A Creem key; one starting `creem_test_` talks to Creem's test API, any other to the live one. |
| `CREEM_WEBHOOK_SECRET` | unset. The secret Creem signs webhooks with. |
| `CREEM_PRODUCT_PRO_MONTHLY` | unset. The Creem product for Pro at $9 a month. Billing is on only with this, the key, and the webhook secret; setting some of the three and not all stops the app at startup. |
| `CREEM_PRODUCT_PRO_YEARLY` | unset: yearly is not offered. The Creem product for Pro at $90 a year. |
| `SENDSCORE_SECRET` | unset. Required when billing is on (at least 32 characters, such as the output of `openssl rand -hex 32`). It signs the account in each checkout, so a public Creem payment link cannot bind a stranger's subscription to an account. |
| `SENDSCORE_PRO_PUBLICATIONS` | `5` newsletters a pro account may monitor |
| `SENDSCORE_FREE_PUBLICATIONS` | `0` newsletters a free account may monitor, with billing on |
| `SENDSCORE_HISTORY_DAYS` | `365` days a pro account's newsletter issues are kept (a free account's are kept as long as a test report, 7 days) |
| `SENDSCORE_PUBLICATION_DAILY_MESSAGES` | `50` messages one monitoring address accepts per UTC day (then a 452) |
| `SENDSCORE_ALERTS_PER_DAY` | `10` alerts one newsletter may send per UTC day |
| `SENDSCORE_ALERTS_PER_ACCOUNT` | `30` alerts one account may send per UTC day, however many newsletters it makes and deletes |
| `SENDSCORE_ALERTS_PER_RECIPIENT` | `20` alerts one address may receive per UTC day, from all accounts |
| `SENDSCORE_ALERTS_PER_HOUR` | `200` alerts per hour for the whole service |
| `SENDSCORE_FREE_DAILY_TESTS` | `25` test addresses per UTC day for a free account |
| `SENDSCORE_PRO_DAILY_TESTS` | `500` test addresses per UTC day for a Pro account |
| `SENDSCORE_ANON_DAILY_TESTS` | `5` test addresses and uploads per UTC day for an anonymous IP. `0`, which turns them off, on a public instance with closed sign-ups. |
| `SENDSCORE_ANON_DAILY_TOTAL` | `100` test addresses and uploads per UTC day for all anonymous visitors together |
| `SENDSCORE_ANON_DAILY_MESSAGES` | `200` messages per UTC day received by all anonymous addresses together |
| `SENDSCORE_DAILY_MB` | `1024` megabytes one account may store per UTC day across test addresses, monitoring addresses, and uploads, and the same for anonymous senders together |
| `SENDSCORE_MAX_STORAGE_MB` | `10240`. At this database size, new mail gets a 452 and uploads a 503, so the disk never fills. Raise it to fit your disk. |
| `SENDSCORE_FREE_DAILY_MESSAGES` | `100` messages per UTC day received by a free account's addresses, together |
| `SENDSCORE_PRO_DAILY_MESSAGES` | `1000` messages per UTC day received by a Pro account's addresses, together |
| `SENDSCORE_MESSAGES_PER_ADDRESS` | `20` messages one test address accepts in its life |
| `SENDSCORE_SMTP_SESSIONS` | `50` SMTP connections open at once |
| `SENDSCORE_SMTP_SESSIONS_PER_IP` | `5` SMTP connections open at once from one sending IP, or one IPv6 /64 |
| `SENDSCORE_SMTP_BUFFER_MB` | `256` megabytes of messages held in memory, counted at twice their size (then a 451) |
| `SENDSCORE_SMTP_ANALYZING` | `8` messages checked at once; more wait up to 30 seconds, then get a 451 |
| `SENDSCORE_SIGNIN_EMAILS_PER_HOUR` | `200` sign-in emails per hour for the whole service |
| `SENDSCORE_OAUTH_REGISTRATIONS_PER_HOUR` | `600` connector registrations per hour for the whole service |
| `SENDSCORE_PRIVACY_URL`, `SENDSCORE_TERMS_URL` | unset. The operator's privacy and terms pages, linked from the footer and the sign-in page when set. |
| `SENDSCORE_TRUST_PROXY` | off. `true` behind a reverse proxy: for a connection from `SENDSCORE_TRUSTED_PROXIES`, the client IP for limits is the last `X-Forwarded-For` entry that is not itself a trusted proxy. The proxy must set the header itself (see Docker), or a client could choose its IP. A public `SENDSCORE_BASE_URL` without it logs a warning at startup, because behind a proxy every visitor would share one IP and one set of limits. |
| `SENDSCORE_TRUSTED_PROXIES` | loopback and the private networks (`127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `fc00::/7`). Comma separated addresses or CIDR ranges the proxy connects from. |

## Newsletter monitoring

A signed-in pro account adds a newsletter at `/newsletters` (the "Newsletters" link in the header) with a name, an optional schedule, an alert address (the account's email by default), and a switch to pause alerts. Each newsletter gets a permanent monitoring address, `m-<token>@<mail domain>`, which never expires. Subscribe it to the newsletter like any reader. A free account sees a page explaining that monitoring is part of Pro.

Every message to the address is checked like a test message, stored with the newsletter, and compared with the newsletter's previous issue (the engine's `Options.Previous`, from the stored fingerprint), so its report lists what changed. A paused newsletter still receives, checks, and keeps its issues, and only sends no alerts. Messages whose subject looks like a subscription confirmation or welcome email (such as "Please confirm your subscription") are stored as signup messages, which are never compared, placed in a slot, or alerted on. The newsletter page lists every message newest first, each with its report and a safe view (`/newsletters/{id}/messages/{report id}`) that shows the text and the links without the HTML, images, or anything that could run, so you can find a confirmation link and open it yourself. SendScore never follows confirm links, as the engine never fetches action links.

A subject is taken for a signup message only on a whole phrase such as "confirm your subscription", or on a looser word such as "welcome" before the newsletter's first issue. The page of a message has a button to correct either way. A retry of a message already saved, which a sender makes when it never saw the reply, is recognized by its hash for 7 days: it is not stored or counted again, and its alerts are decided again, so one lost in a crash still goes out.

The newsletter page shows the monitoring address, the schedule, the time of the next expected issue, the last alert sent, and the timeline, which gives each message's received time (in the newsletter's time zone), subject, verdict, ready to send, the number of changes and whether anything got worse, and a "late" mark for an issue that arrived after its deadline. Edit is at `/newsletters/{id}/edit`. Delete asks on a page of its own (`/newsletters/{id}/delete`) and then removes the newsletter, its messages, and its alerts.

### Schedule

A schedule is the days of the week an issue goes out, a local time (HH:MM), an IANA time zone, and a grace period in minutes (default 30, at most 600). With no days set there is no schedule, so issues are still compared but none is expected. Each slot is built from the local date and time, so a 09:00 issue in America/Toronto is expected at 13:00 UTC in summer and 14:00 UTC in winter. An issue counts for the nearest slot (the span between the midpoints to the slots before and after), and is late when it arrives after that slot's time plus the grace period.

### Alerts

An alert address other than the account's own has to accept first, because alerts go out through the operator's sending account and quote text from a message anyone can send. Saving one emails it a confirmation link, which works for 24 hours and only shows a button, so a mail scanner cannot accept for it, and alerts keep going to the old address until then. Each alert carries a link that stops every alert to that address from this instance; the opt-out holds across accounts, and only a new confirmation lifts it.

Alerts are emailed through SES from `SENDSCORE_ALERT_FROM` to the newsletter's alert address, as plain text and simple HTML with no tracking. Each says why it was sent and links to the newsletter page, where alerts can be redirected, paused, or rescheduled. One is sent:

- when a new issue is worse than the previous one, meaning a check that fails now and did not before, a change the engine marks as worsened, or ready to send going from yes to no;
- when the expected issue has not arrived by the slot's time plus the grace period (a late issue that arrives before the heartbeat runs cancels it);
- when a second issue arrives for the same slot (that alert also lists anything that got worse).

Each alert is written to the `alerts` table before it is sent, keyed by the newsletter, the kind, and the report or the slot, so one issue or one missed slot never sends twice, and a restart never resends. A newsletter sends at most `SENDSCORE_ALERTS_PER_DAY` alerts a UTC day, with further caps per account, per recipient, and per hour for the service; past any of them an alert is recorded as capped and not sent. Quoted subjects and names are cut to 120 characters. A failed send is retried after 1, 5, 15, 60, and then every 240 minutes, for 24 hours, so an SES outage or a key rotation loses nothing, and given up at once only when SES says retrying cannot help. An alert left half sent by a process that stopped is marked failed rather than sent again. Without SES keys, alerts are written to the log instead.

The heartbeat runs every minute. For each scheduled newsletter that is not paused, it finds the latest slot whose deadline has passed and sends the missed-issue alert once, unless an issue arrived in that slot. Slots due before the newsletter was created or last edited, and deadlines more than a day old (after a long outage), are not reported.

### Try it locally

1. Put `SENDSCORE_PRO_EMAILS=you@example.com` in `.env.local`, run `go run .`, and sign in as that address (the link is in the log without SES).
2. Open http://127.0.0.1:3014/newsletters, press "Add a newsletter", and save it. Its page shows the address, such as `m-abcdefghijklmnop@localhost`.
3. Deliver a saved email to it twice, changing it in between to see the comparison (for example, delete its `List-Unsubscribe` line the second time, which is worse and sends an alert to the log):

   ```sh
   go run ./cmd/sendtest -to m-<token>@localhost testdata/sample.eml
   go run ./cmd/sendtest -to m-<token>@localhost changed.eml
   ```

4. Reload the newsletter page: both issues are listed, and the second report has a Changes section.

To see a missed-issue alert, give the newsletter a schedule a minute or two from now with a grace period of 0, and wait for the heartbeat.

## Connector (OAuth)

To connect Claude or another MCP client, add `https://sendscore.example.com/api/mcp` as a custom connector (locally, `http://127.0.0.1:3014/api/mcp`). You will be asked to sign in and allow access. Nothing needs pasting, because the client finds the sign-in on its own, as the MCP authorization spec describes (OAuth 2.1 with PKCE).

1. An unauthenticated call to `/api/mcp` gets a 401 with `WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource/api/mcp"` (and `error="invalid_token"` when a token was sent but is no good).
2. `/.well-known/oauth-protected-resource` (and its `/api/mcp` variant) is RFC 9728 metadata naming the app as the authorization server, and `/.well-known/oauth-authorization-server` is RFC 8414 metadata. There is also `/.well-known/mcp/server-card.json`.
3. The client registers itself at `POST /oauth/register` (RFC 7591). Clients are public, so a request for a secret is registered without one, and the reply says `token_endpoint_auth_method` is `none`. A redirect URI must be https, http on 127.0.0.1 or localhost, or a native app's own scheme (such as `cursor://` or `vscode://`, which those editors use), with no fragment or wildcard; unusable ones are dropped, and a list with none left is refused. Each network may register 120 clients an hour, and the whole service `SENDSCORE_OAUTH_REGISTRATIONS_PER_HOUR`, since hosted clients such as claude.ai register from a few shared servers. At 10,000 registrations, a new one first deletes the oldest clients that are more than an hour old and hold no live token or unused code; when none can go, it gets a 503 with `temporarily_unavailable`, never a `client_id` that does not exist. A name that claims to be SendScore is not kept.
4. `GET /oauth/authorize` sends a signed-out visitor through email sign-in and back, then shows a consent page naming the client, the account, and the full redirect URI it sends you to, with Allow and Deny. It checks the client, the `redirect_uri` (an exact match, except that an http loopback URI matches on any port, as RFC 8252 section 7.3 requires; it may be left out when the client registered only one), PKCE with `S256`, and `resource` (RFC 8707), which must be `<base>/api/mcp` when given, and passes `state` through. A request that fails these checks is shown as an error page and never redirected without the user seeing a page, since anyone can register a redirect URI (RFC 9700 section 4.11.2); Deny on the consent page goes back to the client with `access_denied`. An account may connect 20 apps at once. Allow returns a single-use code that expires in 10 minutes, bound to the client, the redirect URI, the user, and the PKCE challenge, along with `iss` (RFC 9207).
5. `POST /oauth/token` swaps the code and its `code_verifier` for an access token (an hour) and a refresh token (30 days). The token request must send the same `redirect_uri` when the authorization request named one, and may leave it out when it did not (RFC 6749 section 4.1.3). A refresh token is used once. Each refresh returns a new pair; the same refresh token sent again within 30 seconds (a retry, or two workers refreshing at once) gets another new pair, and sent again later it revokes every token of that connection. A code used twice also revokes them.

OAuth tokens (`ss_oat_...`) work only on `/api/mcp`, where an API token works too. They act for the user who allowed them, so ownership and the daily allowance apply as for API tokens. `/account` lists connected apps, with the date each was first allowed and a Disconnect button that revokes their tokens. All codes and tokens are stored only as SHA-256 hashes.

To try it locally, run `npx @modelcontextprotocol/inspector`, choose Streamable HTTP with `http://127.0.0.1:3014/api/mcp`, and use its OAuth flow; the sign-in link is in the app's log when SES is off.

## API

Every `/api/v1/` route and `/api/mcp` take an API token from the account page in the `Authorization` header:

```sh
curl -H "Authorization: Bearer ss_live_..." -X POST https://sendscore.example.com/api/v1/test-addresses
```

A missing, unknown, or revoked token gets a 401 (`{"error": ...}` on `/api/v1/`, and a plain 401 with `WWW-Authenticate: Bearer` on `/api/mcp`). Addresses made with a token belong to its account, and the wait, report, and MCP tools answer only for that account's addresses, with a 404 for anyone else's. The report page `/r/{id}`, its `/r/{id}/json`, and the address page `/t/{token}` stay viewable by their unguessable links. A report page shows its test address and the link to send again only to whoever made the address (its account, or for an anonymous address, the browser that made it), since a shared report link should not let anyone else send to it. Uploads made while signed in belong to the account, so the report API and `get_report` return them. `sendscore mcp` sends the token from `SENDSCORE_TOKEN`.

- `POST /api/v1/test-addresses` returns `address`, `token`, `expires_at`, `wait_url`, and `page_url`.
- `GET /api/v1/test-addresses/{token}/wait?timeout=30` long-polls (at most 50 seconds, below common proxy timeouts) and returns `{"status": "received", "report_id", "report_url", "verdict"}` or `{"status": "not_received"}`. It returns the newest message at the address, even one that arrived before the call. To check a second send to the same address, add `&after=<report_id>` with the earlier report, and only a newer message counts; an `after` that is not a report from this address is a 400. The page `/t/{token}?after=<report_id>` waits the same way. Waits keep working after the address expires, for as long as its reports are kept; when the address has expired and no matching message arrived, the wait answers 410 at once (and the page says the address expired). An account may hold 5 waits open at once (more get a 429), and the service 200.
- `GET /api/v1/reports/{id}` returns the verdict JSON, for a report of one of the token owner's test addresses, uploads, or newsletters.
- `GET /api/v1/publications` returns `{"publications": [...]}`, the token owner's newsletters, each with `id`, `name`, `address`, `schedule` (`days`, `time`, `time_zone`, `grace_minutes`, and `description`, or null), `alert_email`, `paused`, `page_url`, `latest` (the newest issue), and `last_alert`.
- `GET /api/v1/publications/{id}` returns one of them with `reports`, its 50 newest messages, each with `report_id`, `kind` (issue or signup), `received_at`, `subject`, `verdict`, `ready_to_send`, `changes`, `worsened`, `late`, and `report_url`. Another account's newsletter is a 404.

- `/api/mcp` is the remote MCP connector (streamable HTTP, with the token as above) with `get_test_address`, `wait_for_message` (with an optional `after_report_id`, as `after` above), `get_report`, and `compare_to_previous`. The tools live in the engine repository's `mcpserver` package; here they read the database directly. The connector also has `list_publications`, which returns the same list as `GET /api/v1/publications`; it is added here, since monitoring is a feature of the app.

Addresses accept mail for 24 hours; reports are kept for 7 days. A message is checked once per transaction and for one test address: a repeated `RCPT` for the same address is accepted once, and a second address gets a 452, so the sender delivers it separately. A `MAIL FROM` with control characters or angle brackets gets a 501. Uploads and messages are limited to 25 MB, and a larger upload is refused, never cut short.

The receiver bounds volume. A monitoring address accepts 50 messages a UTC day (`SENDSCORE_PUBLICATION_DAILY_MESSAGES`), which no newsletter comes near, and its messages do not count against the account's daily test messages. A test address accepts 20 messages in its life (then a 550 at `RCPT`), an account's addresses together accept 100 a UTC day (then a 452), one connection delivers 10 messages (then a 451 at `MAIL`, so the sender reconnects), and 50 connections may be open at once, 5 from one IP or IPv6 /64 (then a 421), for at most 20 minutes each. A message counts against these once it has arrived, all of them or none, so a stalled or refused body costs nothing. Account bytes, the database size limit, and the memory and analysis limits in the table above bound the rest. Plan memory for `SENDSCORE_SMTP_BUFFER_MB` on top of the process, and set `GOMEMLIMIT` on a small server. Each read of a message body has 60 seconds, so a slow sender is not cut off, up to 10 minutes for the whole message; a body that stops arriving gets a 451, so the sender retries rather than bouncing. At most 4 uploads are read and checked at once, 1 per network (more get a 503). An upload counts against the daily limit before its body is read, whether or not it turns out to be a message.

Upload reports say they came from an upload, and mark the sending IP and envelope sender as supplied by the uploader, since SendScore did not see the delivery. SPF and reverse DNS are checked only when the sending IP is given, and TLS is never checked for an upload.

On shutdown (SIGTERM), open waits answer `not_received` at once, and uploads and SMTP sessions get up to 70 seconds to finish their checks, save, and send any alert; anything still open after that is dropped and retried by the sender. The heartbeat then gets up to 15 seconds to finish. Give the process manager a stop timeout of 90 seconds (systemd's default). A second signal stops the process at once.

## Billing

Billing is off unless you set the Creem settings above.

With the Creem settings above, the account page has a Plan section. A free account sees "Upgrade to Pro" with a monthly and a yearly button, which open a Creem checkout. Creem decides. Returning from the checkout grants nothing, and Pro turns on when Creem's webhook says the payment went through, usually within seconds. A Pro account sees when it is paid through and a "Manage billing" button for Creem's own page (card, invoices, and cancelling). A failed renewal shows that Creem is retrying, and Pro stays on meanwhile. A granted account says so and has no billing buttons. Without the settings, none of this shows and nothing changes.

Creem posts events to `POST /api/creem/webhook`, which takes no session or CSRF token and is authenticated by the `creem-signature` header alone (the hex HMAC-SHA256 of the raw body). Point the Creem webhook there. Every event is stored in `creem_events` (its id is the primary key, so an event already applied is never applied again), and the subscription in `subscriptions`. An event recorded and not marked applied, as after a crash, is applied when Creem retries it. A bad signature is 401, a body over 1 MB is 413, an event with no id is 500, anything understood or deliberately ignored is 200, and a failure while applying gives the event back and answers 500 so Creem retries. An event older than the newest one applied is recorded and ignored. The account comes from the signed claim the checkout put in the metadata, then the bound subscription id, then the bound customer id, and never from an email address. Past due only keeps a plan that was already paid, a product this install does not sell grants nothing, only the bound subscription can end a plan, a healthy plan is never rebound to another customer, and a running period end is never wiped.

When Pro lapses (paused, expired, or cancelled), nothing is deleted. Newsletters stay listed and their addresses keep receiving mail, but no alert is sent and the heartbeat skips them, new issues are kept for 7 days as on the free plan, and adding a newsletter is refused with a link to the plan. Paying again turns it all back on.

## Docker

The `Dockerfile` builds a static binary (`CGO_ENABLED=0`, `-trimpath`) with the Go toolchain `go.mod` pins, into a distroless image (`gcr.io/distroless/static-debian13:nonroot`, with CA certificates and tzdata) that runs as uid 65532. Both base images are pinned by digest.

A build needs only this repository, and uses the engine version in `go.mod`. `ENGINE_VERSION` picks another (a tag, a commit, or a pseudo-version).

```sh
docker build -t sendscore-app .
docker build --build-arg ENGINE_VERSION=v0.2.0 -t sendscore-app .
```

To run it, with the certificate directory mounted, use this.

```sh
docker run -d --name sendscore --env-file .env --stop-timeout 90 \
  -p 25:2525 -p 127.0.0.1:3014:3014 \
  -v sendscore-data:/data \
  -v /srv/sendscore/certs:/certs:ro \
  sendscore-app
```

With Compose, `docker compose up -d --build` does the same from `compose.yaml` and a `.env` next to it.

- The image listens on `0.0.0.0:3014` (web) and `0.0.0.0:2525` (SMTP). Map port 25 on the host to 2525 in the container, since the container runs as non-root and cannot bind 25 itself, and point the domain's MX record at the host.
- The database is `/data/sendscore.db` on the volume `/data`. Copying the file of a running database can give a torn copy, so back up with `docker compose exec app sendscore-app backup /data/backup-2026-10-31.db`, which writes a consistent copy to a new file while the app runs, then move that file off the server.
- Publish 3014 on 127.0.0.1 only, and put a reverse proxy with TLS (Caddy, nginx, or similar) in front of it. Caddy's `reverse_proxy` sets `X-Forwarded-For` for you. nginx needs `proxy_set_header X-Forwarded-For $remote_addr;`, because a plain `proxy_pass` passes on whatever the client sent.
- For STARTTLS, bind mount the directory holding the mail domain's certificate read-only and point `SENDSCORE_TLS_CERT` and `SENDSCORE_TLS_KEY` at the files in it, such as `/certs/fullchain.pem` and `/certs/privkey.pem`. Mount the directory rather than the files, because a file bind mount keeps the old file after a renewal replaces it, and the app reloads the files when they change. The key must be readable by uid 65532. Certbot's own keys are root only, so have a deploy hook copy both files into `/srv/sendscore/certs` and `chown 65532` them.
- The settings that matter in production are `SENDSCORE_BASE_URL` (the public https URL, which the image otherwise sets to `http://127.0.0.1:3014` for a local run), `SENDSCORE_MAIL_DOMAIN`, `SES_ACCESS_KEY_ID` and `SES_SECRET_ACCESS_KEY` (required once the base URL is https), `SENDSCORE_MAIL_FROM` and `SENDSCORE_ALERT_FROM`, `SENDSCORE_PRO_EMAILS` with your own address, `SENDSCORE_TRUST_PROXY=true` behind the proxy, the TLS files, and the blocklist and billing settings above.
- On SIGTERM the app gives open sessions up to 70 seconds to finish, so stop it with a timeout of 90 seconds (`--stop-timeout 90`, `docker stop -t 90`, or `stop_grace_period: 90s` as in `compose.yaml`). Docker's default of 10 seconds would cut them off.
- `GET /healthz` answers 200 when the database answers, the heartbeat ran in the last 5 minutes, and the SMTP listener takes connections, and 503 otherwise. The image's `HEALTHCHECK` runs `sendscore-app healthcheck`, which calls it, since the distroless image has no shell or curl.

## Not built yet

Deploy scripts. Nothing is deployed. Self-hosting is documented on the website.

## Develop

```sh
go vet ./... && go test ./... && go test -race ./... && go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

`go.mod` pins the toolchain (`toolchain go1.26.10`), so a build never uses an older Go with known standard library vulnerabilities; move it forward when a new patch release is out.

No em or en dashes anywhere. Commits: short one-line messages, no attribution lines.

## License

AGPL-3.0. The engine and CLI it imports are MIT.
