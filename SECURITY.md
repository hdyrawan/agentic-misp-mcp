# Security Policy

## Project status

`agentic-misp-mcp` is an MIT-licensed project in early development. It has been tested with mocked MISP responses only; live MISP compatibility testing and production security review are still pending. Do not treat the current branch or any `0.1.x` package as production software.

## Supported versions

| Version | Status |
| --- | --- |
| `main` / unreleased `0.1.x` | Early development; security fixes are best-effort before a stable release. |
| Older commits and branches | Not supported. |

## Reporting vulnerabilities

Please open a private security advisory or contact the maintainers through the repository owner's preferred private channel. If private reporting is unavailable, open a public issue with only a high-level description and request a secure contact path.

Do not include working exploit code, real MISP URLs, real event data, API keys, authentication headers, bearer tokens, passwords, cookies, or other secrets in reports, issues, pull requests, logs, screenshots, or test fixtures.

## Secret handling expectations

- `MISP_API_KEY` must be provided only through runtime environment variables.
- MCP tools must never accept API keys, tokens, passwords, authorization headers, or raw credential material as arguments.
- `config-check` validates that secrets are present but redacts values.
- Audit records must sanitize sensitive argument names and must not contain authorization headers or MISP API keys.
- Docker images, CI logs, documentation examples, and test fixtures must use placeholders only.

## Security boundaries

This project is workflow-first, not a raw MISP API wrapper. It must not expose raw MISP API proxying, shell execution, unrestricted filesystem access, or generic user/organisation/server/settings admin tools. Write workflows are disabled by default and must remain policy- and approval-gated when enabled.
