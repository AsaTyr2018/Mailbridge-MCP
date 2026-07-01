# Mailbridge MCP

Mailbridge MCP is a self-hosted mail bridge for Codex and other MCP clients. Users configure their own named IMAP/SMTP accounts in a small web admin UI. Codex accesses only the accounts owned by the bearer-token user through MCP tools for sync, search, reading, drafting, and guarded sending.

The web UI is not a mail client. It is for account setup, health/status, policy, token display, and approvals.

## Features

- Multiuser login with no default user.
- First registered user becomes admin.
- Per-user MCP bearer tokens.
- User-owned mail accounts.
- IMAP sync and SQLite FTS indexing.
- SMTP draft/send flow.
- Interactive sends require displaying final content and active user `ok`.
- Admin menu for registration on/off and user lock/delete/token revoke.
- Gmail-style search operators such as `from:`, `to:`, `subject:`, `newer_than:`, `after:`, `has:attachment`, `filename:`, `larger:`.

## Security Notes

Do not expose Mailbridge to the internet without HTTPS. Put it behind a reverse proxy such as Caddy, nginx, or Traefik.

Runtime data in `./data` contains the SQLite database, encrypted mail credentials, and encryption/session key material. Never commit or publish it.

## Quickstart

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and set the public URL plus allowed hosts/origins for your deployment.

Start:

```bash
docker compose up -d --build
```

Open the web UI and register the first user:

```text
http://localhost:18082/register
```

The first registered user becomes admin. After login, the dashboard displays that user's personal MCP bearer token.

## Codex Configuration

Use the personal token shown after login:

```toml
[mcp_servers.mailbridge]
url = "https://mailbridge.example.com/mcp/"
http_headers = { Authorization = "Bearer YOUR_PERSONAL_MAILBRIDGE_TOKEN" }
startup_timeout_sec = 10
tool_timeout_sec = 60
enabled = true
```

For local testing:

```toml
[mcp_servers.mailbridge]
url = "http://127.0.0.1:18082/mcp/"
http_headers = { Authorization = "Bearer YOUR_PERSONAL_MAILBRIDGE_TOKEN" }
enabled = true
```

## MCP Tools

- `list_accounts`
- `get_account_status`
- `sync_account`
- `search_mail`
- `get_message`
- `get_thread`
- `analyze_thread`
- `search_contacts`
- `list_calendar_events`
- `create_draft`
- `list_drafts`
- `send_draft`

Calendar/contact tools are present as policy-controlled placeholders until CalDAV/CardDAV/provider sync is configured.

## Search Operators

`search_mail` supports plain full-text search and common Gmail-like filters:

```text
from: to: cc: bcc: deliveredto:
subject:
"exact phrase" +word -word
after:YYYY/MM/DD before:YYYY/MM/DD older:YYYY/MM/DD newer:YYYY/MM/DD
newer_than:7d older_than:6m
in: label:
is:read is:unread is:starred is:important is:muted
has:attachment filename:
size: larger: smaller:
list: rfc822msgid:
```

Gmail-specific metadata that IMAP does not generally provide is ignored safely rather than passed raw to SQLite FTS.

## Environment

See `.env.example` for all common settings.

Important variables:

- `MAILBRIDGE_PUBLIC_URL`
- `MAILBRIDGE_ALLOWED_HOSTS`
- `MAILBRIDGE_ALLOWED_ORIGINS`
- `MAILBRIDGE_SECURE_COOKIES`

The default configuration is localhost-only:

```env
MAILBRIDGE_PUBLIC_URL=http://127.0.0.1:18082
MAILBRIDGE_ALLOWED_HOSTS=127.0.0.1,127.0.0.1:8080,127.0.0.1:18082,localhost,localhost:8080,localhost:18082
MAILBRIDGE_ALLOWED_ORIGINS=http://127.0.0.1:18082,http://localhost:18082
MAILBRIDGE_SECURE_COOKIES=false
```

In Docker this means:

- The application listens on `0.0.0.0:8080` inside the container.
- Compose publishes it as `127.0.0.1:18082:8080` on the host by default.
- `MAILBRIDGE_ALLOWED_HOSTS` validates the HTTP `Host` header for MCP requests; it is not the socket bind address.
- Host-local access uses `http://127.0.0.1:18082`.
- Container-internal access may use `http://127.0.0.1:8080`.

For LAN access, set the host/IP explicitly:

```env
MAILBRIDGE_BIND=0.0.0.0:18082
MAILBRIDGE_PUBLIC_URL=http://192.168.1.50:18082
MAILBRIDGE_ALLOWED_HOSTS=192.168.1.50,192.168.1.50:18082
MAILBRIDGE_ALLOWED_ORIGINS=http://192.168.1.50:18082
MAILBRIDGE_SECURE_COOKIES=false
```

For internet exposure, use HTTPS behind a reverse proxy:

```env
MAILBRIDGE_PUBLIC_URL=https://mailbridge.example.com
MAILBRIDGE_ALLOWED_HOSTS=mailbridge.example.com
MAILBRIDGE_ALLOWED_ORIGINS=https://mailbridge.example.com
MAILBRIDGE_SECURE_COOKIES=true
```

Use `MAILBRIDGE_SECURE_COOKIES=true` when serving over HTTPS.

## License

PolyForm Noncommercial License 1.0.0. Commercial use is not permitted without a separate commercial license. See [LICENSE](LICENSE).
