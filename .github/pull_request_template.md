## Summary

Describe the change and why it is needed.

## Scope

- [ ] Web UI
- [ ] MCP tools/protocol behavior
- [ ] IMAP/SMTP sync/search/read
- [ ] Contacts/calendar sync
- [ ] Send/draft workflow
- [ ] Security/audit/session behavior
- [ ] Privacy/data retention
- [ ] Docker/deployment
- [ ] Documentation

## Privacy and security impact

Explain what user data this change stores, reads, sends, deletes, logs, or exposes.

- Data touched:
- Retention impact:
- Token/credential impact:
- User consent/policy impact:

## Verification

List the checks you ran.

- [ ] `python -m py_compile $(find mailbridge -name '*.py' -print)`
- [ ] Docker build
- [ ] Manual web UI check
- [ ] MCP tool check
- [ ] Migration check
- [ ] Not applicable

## Deployment notes

Mention any migration, environment variable, reverse proxy, token, or user-action requirements.

## Safety checklist

- [ ] No runtime `./data` files, databases, keys, tokens, passwords, or private mail/contact/calendar data are committed.
- [ ] User/account ownership boundaries are preserved.
- [ ] MCP token values are never logged or displayed after one-time reveal.
- [ ] Send behavior still requires interactive approval or prior scoped automation consent.
- [ ] Public deployment/security notes are updated if exposure risk changes.
