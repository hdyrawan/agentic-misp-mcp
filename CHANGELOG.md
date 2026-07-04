# Changelog

All notable changes to this project will be documented in this file.

This project is in **early development**. It has been tested with mocked MISP responses only;
live MISP compatibility testing is still pending.

## Unreleased

### Added

- Added read-only MCP tools for IOC search, IOC investigation, event summarization, warninglist
  checks, and deterministic IOC reports (`search_ioc`, `investigate_ioc`, `summarize_event`,
  `check_warninglists`, `generate_ioc_report`).
- Added event intelligence and pivoting workflows (`pivot_ioc`, `find_related_iocs`,
  `extract_event_iocs`, `explain_event_context`, `find_events_by_tag`).
- Added deterministic structured and Markdown report generation for IOCs and MISP events
  (`generate_event_report`, `generate_markdown_ioc_report`, `generate_markdown_event_report`).
- Added JSONL audit logging for MCP tool calls.
- Added Docker and Docker Compose examples.
- Added configuration and security documentation.

### Changed

- Stabilized analyst-oriented report outputs around deterministic JSON and Markdown schemas.
- Improved IOC investigation with scoring, verdicts, related IOC extraction, tag-derived
  context, and recommended actions.

### Security

- Kept the MCP server read-only by default.
- No write, admin, publish, tagging, sighting submission, or raw MISP API proxy tools are
  implemented.
- MISP API key is loaded only from environment variables.
- TLS verification is enabled by default.
- Tool calls are audited without logging secrets.

### Known limitations

- Tested with mocked MISP responses only.
- Live MISP compatibility testing is pending.
- Warninglist endpoint behavior may vary by MISP version.
- Galaxy/Object parsing is currently tag-derived and does not fully parse nested MISP
  Galaxy/Object structures.
