# Changelog

## 0.4.3

- Return Magic Login links by default from `get_web_ui_link` for personal user tokens.
- Keep automation-token calls non-failing by returning normal Web UI links without login links.

## 0.4.2

- Add optional single-use Magic Link generation to `get_web_ui_link`.
- Add configurable Magic Link TTL and Web session TTL.
- Block automation tokens from creating Web login links.

## 0.4.1

- Add `get_web_ui_link` MCP tool for returning the configured Mailbridge Web UI URL on user request.

## 0.4.0

- Add non-blocking background sync jobs with progress and cancellation.
- Add automatic recent-mail sync every five minutes by default.
- Add cached IMAP flag reconcile for fresher read/unread state.
- Add user and admin mail-index cache flush controls.
- Add MCP sync-job tools and mail mutation tools for mark, trash, and folder-backed labels.
- Fix `is:read` and `is:unread` matching for IMAP `\Seen` flags.

## 0.3.3

- Add scoped automation send consents for approved autonomous sends.
- Add MCP tools to list, create, and revoke automation consents.
- Enforce automation consent account, recipient/domain, expiry, and daily send-limit checks in `send_draft`.
- Keep automation tokens read-only for consent management so personal user approval is required to grant send consent.

## 0.3.2

- Add MCP draft management tools: `get_draft`, `approve_draft`, `reject_draft`, and `delete_draft`.
- Require `user_ok=true` for MCP draft approval after the client has shown the draft content to the user.
- Add persisted draft attachments for forward drafts and send them through SMTP with `send_draft`.
- Include draft attachment metadata in send approval previews.

## 0.3.1

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
