# Security Policy

## Project status

`agentic-misp-mcp` is an MIT-licensed project with `0.2.x` releases validated for the documented MCP server scope: workflow-first read tools plus policy- and approval-gated controlled writes. `v0.2.1` passed live validation against MISP `2.5.42` using Docker, stdio transport, MCP Inspector, runtime-only secrets, audit logging, production approval mode, and the documented HTTP bind guardrail. Treat production readiness as bounded to that scope; it is not a raw MISP API proxy, SIEM/SOAR platform, or generic MISP administration surface.

## Supported versions

| Version | Status |
| --- | --- |
| `0.2.x` | Supported for security fixes within the documented production-ready MCP scope. |
| `main` / unreleased changes | Best-effort support until released; security fixes may land here before the next `0.2.x` release. |
| `0.1.x` | Not supported. Upgrade to `0.2.x`. |
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
