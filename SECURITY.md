# Security Policy

Mailbridge handles mail credentials and private mail content.

Mailbridge is licensed under the PolyForm Noncommercial License 1.0.0. Commercial use requires a separate commercial license.

## Deployment

- Use HTTPS for internet exposure.
- The default allowed-host/origin configuration is localhost-only.
- Set `MAILBRIDGE_ALLOWED_HOSTS` and `MAILBRIDGE_ALLOWED_ORIGINS` explicitly for LAN or public domains.
- Set `MAILBRIDGE_SECURE_COOKIES=true` behind HTTPS.
- Keep `./data` private and backed up securely.
- Do not commit runtime data, databases, keys, or tokens.
- Rotate user MCP tokens after suspected exposure.

## Reporting

Please open a private security advisory or contact the maintainer directly before publishing vulnerabilities.
