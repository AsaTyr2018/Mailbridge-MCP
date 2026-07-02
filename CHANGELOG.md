# Changelog

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
