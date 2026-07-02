# Mailbridge MCP

Mailbridge MCP is a self-hosted mail bridge for MCP-capable clients such as Codex CLI, Claude Desktop, custom agents, and internal automation tools.
Users configure their own named IMAP/SMTP accounts in a focused web admin UI.
MCP clients access only the accounts owned by the bearer-token user through MCP tools for sync, search, reading, drafting, and guarded sending.

The web UI is not a mail client. It is for account setup, health/status, policy,
token management, audit, and security oversight.

## Clean and Secure

Mailbridge is designed so mail credentials stay inside Mailbridge.

- IMAP/SMTP passwords are encrypted locally and are never exposed through MCP tools.
- MCP clients receive mail metadata/content only through scoped tools such as `search_mail` and `get_message`.
- The MCP bearer token identifies a user, but the token itself is never written to audit logs.
- Each bearer token has a separate random Token ID such as `tkn_33DAD8` for audit and troubleshooting.
- Full bearer tokens are shown only once during registration or renewal.
- Renewing a token invalidates the previous token immediately.
- MCP usage is audited with timestamp, user, Token ID, client, MCP version, IP, user-agent, action, result, and latency.

## Features

- Multiuser login with no default user.
- First registered user becomes admin.
- Per-user MCP bearer tokens and Token IDs.
- User-owned mail accounts.
- IMAP sync and SQLite FTS indexing.
- Privacy-aware mail index modes: `metadata_only`, `headers`, and `full_text`.
- User-owned Contact/Calendar sync profiles.
- CardDAV contact sync into a local searchable contact index.
- CalDAV calendar sync into a local event index.
- ActiveSync endpoint test, folder discovery, and Mailcow/SOGo item sync via discovered DAV collections.
- Mail history page for indexed message metadata.
- Draft queue page without web approval buttons; approval is handled through the MCP policy flow.
- SMTP draft/send flow with guarded send policies.
- Interactive sends require displaying final content and active user `ok`.
- Dashboard Bearer Security summary with last use, client, IP, action, and status.
- Security Audit for MCP token usage.
- User-scoped audit views; admins can inspect global usage.
- Admin menu for registration on/off and user lock/delete/token renew.
- Gmail-style search operators such as `from:`, `to:`, `subject:`, `newer_than:`, `after:`, `has:attachment`, `filename:`, `larger:`.

## Web UI

The web UI provides these operational pages:

- `Accounts`: runtime status, account list, hidden Add Account form, token renewal, Bearer Security summary.
- `Queue`: pending MCP-created drafts. No approve/reject buttons are shown here.
- `Mail History`: recent indexed mail metadata.
- `Audit`: user-scoped web and MCP actions.
- `Security Audit`: MCP bearer token usage with Token ID, client, IP, intent, result, and latency.
- `Admin`: registration switch and user management.

## Security Notes

Mailbridge is currently recommended for local or trusted LAN use.

Public internet exposure is not recommended yet. Several hardening topics still need dedicated work before this should be treated as a public-facing service, including rate limiting, MFA, stricter session controls, SSRF protection for IMAP/SMTP hosts, validated automation-consent rules, and abuse detection.

If you still expose Mailbridge beyond a trusted network, use HTTPS behind a reverse proxy such as Caddy, nginx, or Traefik, set explicit allowed hosts/origins, enable secure cookies, disable registration after creating the first admin user, and use strong passwords.

Runtime data in `./data` contains the SQLite database, encrypted mail credentials, and encryption/session key material. Never commit or publish it.

## Quickstart

Start:

```bash
docker compose up -d --build
```

Open the web UI and register the first user:

```text
http://localhost:18082/register
```

The first registered user becomes admin. After registration or token renewal, the full personal MCP bearer token is shown once. The dashboard later shows only the Token ID.

## MCP Client Configuration

Any Streamable HTTP MCP client can connect with the personal token shown once after registration or renewal:

```toml
[mcp_servers.mailbridge]
url = "https://mailbridge.example.com/mcp/"
http_headers = { Authorization = "Bearer YOUR_PERSONAL_MAILBRIDGE_TOKEN" }
startup_timeout_sec = 10
tool_timeout_sec = 60
enabled = true
```

Codex CLI example for local testing:

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
- `list_sync_profiles`
- `sync_profile`
- `create_contact`
- `update_contact`
- `delete_contact`
- `create_calendar_event`
- `update_calendar_event`
- `delete_calendar_event`
- `create_draft`
- `list_drafts`
- `send_draft`

Calendar/contact tools read normalized local data from configured sync profiles. CardDAV and CalDAV profiles perform direct DAV item sync. ActiveSync profiles perform the ActiveSync handshake and folder discovery first; for Mailcow/SOGo-style servers, discovered `vcard` and `vevent` collections are mapped to the matching DAV collections and imported into the same local indexes.

## Contact And Calendar Sync

On an account page, add one or more sync profiles:

- `carddav` with kind `contacts`, for example `https://mail.example.com/SOGo/dav/user@example.com/Contacts/personal/`
- `caldav` with kind `calendar`, for example `https://mail.example.com/SOGo/dav/user@example.com/Calendar/personal/`
- `activesync` with kind `contacts` or `calendar`, for example `https://mail.example.com/Microsoft-Server-ActiveSync`

If the profile username or password is left empty, Mailbridge uses the account IMAP username/password internally. Those credentials stay encrypted in Mailbridge and are not exposed to MCP clients.

Useful operations:

- `Test` verifies authentication and provider reachability.
- `Discover` lists DAV resources or ActiveSync folders.
- `Sync` imports CardDAV contacts, CalDAV events, or ActiveSync-discovered Mailcow/SOGo contact/calendar collections into the local database.

MCP clients can then use `search_contacts` and `list_calendar_events` without receiving the underlying mail account password.

Writable contact/calendar tools use the same account-scoped MCP permissions as read tools. They write to CardDAV/CalDAV directly, or to Mailcow/SOGo DAV collections discovered from an ActiveSync profile. Contact tools accept display name, email, phone, and company fields. Calendar tools accept title, start/end timestamps, location, description, and attendee email lists.

## Mail Privacy Modes

New accounts default to `metadata_only`.

- `metadata_only`: stores folder, IMAP UID, message ids, sender/recipient fields, subject, date, flags, and size. It does not store body text, snippets, attachment names, or full headers.
- `headers`: stores full headers but no body text, snippets, or attachment names.
- `full_text`: stores extracted text body and snippets for local full-text search.

When `get_message` is called for a message without locally stored body text, Mailbridge fetches the body live from IMAP, returns it to the MCP client, and does not persist that body. Switching an existing account from `full_text` to `metadata_only` or `headers` purges already stored body/snippet data for that account.

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

Gmail/Googlemail IMAP and SMTP autodiscovery uses Gmail endpoints and requires a Google App Password. Google Calendar/Contacts DAV access may require OAuth2; Mailbridge does not yet implement Google OAuth.

## Environment

Important variables:

- `MAILBRIDGE_PUBLIC_URL`
- `MAILBRIDGE_ALLOWED_HOSTS`
- `MAILBRIDGE_ALLOWED_ORIGINS`
- `MAILBRIDGE_SECURE_COOKIES`

The default compose file binds to localhost:

```text
http://127.0.0.1:18082/
```

For trusted LAN testing, set `MAILBRIDGE_BIND=0.0.0.0:18082` and add the LAN host or IP to `MAILBRIDGE_ALLOWED_HOSTS` and `MAILBRIDGE_ALLOWED_ORIGINS`.

For internet exposure, use HTTPS behind a reverse proxy and set:

```env
MAILBRIDGE_PUBLIC_URL=https://mailbridge.example.com
MAILBRIDGE_ALLOWED_HOSTS=mailbridge.example.com
MAILBRIDGE_ALLOWED_ORIGINS=https://mailbridge.example.com
MAILBRIDGE_SECURE_COOKIES=true
```

Use `MAILBRIDGE_SECURE_COOKIES=true` when serving over HTTPS.

## Security Audit Fields

Security Audit records MCP bearer-token usage without storing the bearer token:

| Field | Example |
| --- | --- |
| Timestamp | `2026-07-02 08:34:52` |
| User | `asatyr` |
| Token ID | `tkn_33DAD8` |
| Client | `Codex CLI` |
| Client Version | `1.2026.133` |
| MCP Version | `2025-03-26` |
| IP | `192.168.1.25` |
| User-Agent | `Codex/1.2026.133` |
| Interface | `MCP HTTP` |
| Intent | `search_mail` |
| Result | `ok` |
| Latency | `87 ms` |

This data is intended to support future security rules such as new-IP warnings, unknown-client warnings, stale-token cleanup, and abuse detection.

## License

PolyForm Noncommercial License 1.0.0. Commercial use is not permitted without a separate commercial license.
