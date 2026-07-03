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
- Per-user automation tokens for personal automation clients such as MCP-MASH.
- User-owned mail accounts.
- IMAP sync and SQLite FTS indexing.
- Background sync job queue with progress, cancellation, and non-blocking Web/MCP requests.
- Automatic recent-mail sync every five minutes by default.
- Cached IMAP flag reconcile so read/unread state stays fresh without downloading message bodies.
- User and admin mail-index cache flush controls.
- Privacy-aware mail index modes: `metadata_only`, `headers`, and `full_text`.
- User-owned Contact/Calendar sync profiles.
- CardDAV contact sync into a local searchable contact index.
- CalDAV calendar sync into a local event index.
- ActiveSync endpoint test, folder discovery, and Mailcow/SOGo item sync via discovered DAV collections.
- Mail history page for indexed message metadata.
- Draft queue page without web approval buttons; approval is handled through the MCP policy flow.
- SMTP draft/send flow with guarded send policies.
- MCP draft management for reviewing, approving, rejecting, deleting, and sending drafts.
- Forward drafts can copy selected original message attachments into the draft and send them later.
- Interactive sends require displaying final content and active user `ok`.
- Dashboard Bearer Security summary with last use, client, IP, action, and status.
- Security Audit for MCP token usage.
- Single-use Magic Link generation from `get_web_ui_link` for personal user tokens.
- Web UI and MCP update checks against the configured GitHub branch.
- User-scoped audit views; admins can inspect global usage.
- Admin menu for registration on/off and user lock/delete/token renew.
- Automation-scoped mail actions for move, mark read/unread, trash, and folder-backed labels.
- Gmail-style search operators such as `from:`, `to:`, `subject:`, `newer_than:`, `after:`, `has:attachment`, `filename:`, `larger:`.

## Add-on: MCP-MASH

[MCP-MASH](https://github.com/AsaTyr2018/MCP-MASH) is the companion **Mail Automation Script Host** for Mailbridge.

Mailbridge remains the secure mail gateway: it owns users, mail accounts, encrypted IMAP/SMTP credentials, mail indexing, account-scoped permissions, send policy, and audit.
MCP-MASH is a personal single-user MCP server that stores automation scripts, schedules, and run logs. It connects to Mailbridge with a user-scoped automation token and can only operate on the accounts and permissions granted to that token.

Use MCP-MASH for autonomous local mail workflows such as mailbox rules, scheduled cleanup, account-specific reports, and future report/reply automations while keeping mail account passwords inside Mailbridge.

## Web UI

The web UI provides these operational pages:

- `Dashboard`: runtime status, MCP URL, token renewal, Bearer Security summary.
- `Accounts`: account list and account actions.
- `Sync Jobs`: recent background sync status, progress, and cancellation.
- `Add Account`: guided account creation with email/password autodiscovery and collapsed advanced IMAP/SMTP settings.
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
- `get_web_ui_link`
- `check_for_updates`
- `get_account_status`
- `sync_account`
- `start_sync_account`
- `get_sync_job`
- `list_sync_jobs`
- `cancel_sync_job`
- `search_mail`
- `get_message`
- `get_thread`
- `analyze_thread`
- `list_attachments`
- `get_attachment`
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
- `create_forward_draft`
- `list_drafts`
- `get_draft`
- `approve_draft`
- `reject_draft`
- `delete_draft`
- `send_draft`
- `list_automation_consents`
- `create_automation_consent`
- `revoke_automation_consent`
- `create_automation_token`
- `list_automation_tokens`
- `revoke_automation_token`
- `move_messages`
- `mark_messages`
- `trash_messages`
- `add_label_to_messages`
- `remove_label_from_messages`

`sync_account` now queues a background sync job instead of blocking the MCP request. Use `get_sync_job` or `list_sync_jobs` to inspect progress.

`get_web_ui_link` returns the configured Web UI URL and, for personal user tokens, a single-use Magic Link for browser login by default. Automation tokens receive the normal Web UI links without a login link. The Magic Link TTL defaults to 600 seconds and the resulting Web session TTL defaults to 3600 seconds. Set `include_login_link=false` to return only plain links.

`check_for_updates` compares the running Mailbridge commit with the configured GitHub branch and reports when a newer commit is available. Docker deployments should set `MAILBRIDGE_GIT_COMMIT` during deployment for exact comparisons. Without it, Mailbridge can only detect the current commit when it runs directly from a Git checkout.

Calendar/contact tools read normalized local data from configured sync profiles. CardDAV and CalDAV profiles perform direct DAV item sync. ActiveSync profiles perform the ActiveSync handshake and folder discovery first; for Mailcow/SOGo-style servers, discovered `vcard` and `vevent` collections are mapped to the matching DAV collections and imported into the same local indexes.

Draft tools are intentionally split:

- `list_drafts` lists recent drafts visible to the bearer-token user.
- `get_draft` returns one draft with body text and attachment metadata so the MCP client can show it to the user.
- `approve_draft` requires `user_ok=true` and should only be called after the user has seen and approved the draft content.
- `reject_draft` marks a draft as rejected so it cannot be sent later.
- `delete_draft` removes an unsent draft and stored draft attachments.
- `send_draft` still enforces the account send policy. Interactive policies return a preview and require a second call with explicit OK.

`create_forward_draft` can optionally copy original message attachments into the draft using attachment indices, filenames, or `include_attachments=true`. Stored draft attachments are included in the `send_draft` approval preview and are attached to the SMTP message when the draft is sent.

## Automation Send Consents

Accounts with `mcp_send_mode=interactive_or_approved_automation` or `approved_automation_only` can use scoped automation consents for repeat sends without interactive OK.

Automation consents are not bearer tokens. They are account-local send-policy records that restrict autonomous sends by recipient and/or domain, optional expiry, and optional daily send limit.

Consent tools:

- `list_automation_consents`
- `create_automation_consent`
- `revoke_automation_consent`

Creating or revoking consents requires a personal user MCP token. Automation tokens, including MCP-MASH tokens, may inspect existing consents but cannot grant themselves send approval.

Example consent for a bot-mailer account:

```text
account_id: 1
name: MASH weekly reports
allowed_recipients: hauke@example.com
max_sends_per_day: 5
```

MCP-MASH can then call `send_draft` with that `automation_consent_id`. Mailbridge verifies the draft account, recipients, domains, expiry, and daily limit before sending.

## Automation Tokens

Automation tokens are user-scoped MCP bearer tokens for personal automation clients such as MCP-MASH.

The intended add-on for these tokens is [MCP-MASH](https://github.com/AsaTyr2018/MCP-MASH), a personal automation host that runs scheduled mail scripts through Mailbridge. Mailbridge still enforces the token's user, account, and permission boundaries.

They are not global service tokens. Each automation token belongs to one Mailbridge user, can only see that user's allowed accounts, and carries an explicit permission list such as `list_accounts`, `sync`, `search`, `read`, `move`, `trash`, `mark_read`, `draft`, or `send`.

Additional permissions are available for narrower automation:

- `attachments`: list and read message attachments through `list_attachments` and `get_attachment`.
- `forward`: create forward drafts through `create_forward_draft`.
- `contacts` and `contacts_write`: read or create/update/delete contacts.
- `calendar` and `calendar_write`: read or create/update/delete calendar events.

Mailbridge records automation-token calls in the normal MCP security audit with the token ID and MCP client name. Clients should set a clear MCP `clientInfo.name`, for example `mcp-mash`, so audit rows distinguish autonomous automation from interactive clients such as Codex.

Automation token creation tools return the full token once. The token is not returned again later.

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
