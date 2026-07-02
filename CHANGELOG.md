# Changelog

## Unreleased

- Document MCP-MASH as the companion Mail Automation Script Host add-on for user-scoped automation tokens.
- Add MCP tools for listing/reading message attachments with size-capped base64 output.
- Add MCP tool for creating forward drafts while keeping send policy in `send_draft`.

## 0.3.0

- Add user-scoped automation tokens for personal automation clients such as MCP-MASH.
- Add automation permission and account scoping for MCP calls.
- Add `move_messages` for mailbox rule automation.
- Add explicit automation-client audit attribution and token IDs.
- Split the web UI into Dashboard, Accounts, and Add Account pages.
- Refine Add Account with email/password autodiscovery and collapsed advanced IMAP/SMTP settings.

## 0.2.0

- Add CardDAV, CalDAV, and ActiveSync-backed contact/calendar sync profiles.
- Add account and sync-profile autodiscovery.
- Add MCP tools for listing/syncing profiles, contacts, and calendar events.
- Add MCP write tools for contacts and calendar events.
- Add privacy-aware mail index modes: `metadata_only`, `headers`, and `full_text`.
- Fetch message bodies live from IMAP for privacy-minimal indexes without persisting the body.
- Add Gmail/Googlemail IMAP/SMTP autodiscovery handling and app-password guidance.

## 0.1.0

- Initial Dockerized Mailbridge MCP release.
- Multiuser web UI.
- Per-user MCP bearer tokens.
- User-owned IMAP/SMTP accounts.
- IMAP sync, SQLite FTS search, draft/send workflow.
- PolyForm Noncommercial License 1.0.0.
