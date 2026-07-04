# Changelog

All notable changes to this project will be documented in this file.

This project is in **early development**. It has been tested with mocked MISP responses only;
live MISP compatibility testing is still pending.

## [Unreleased]

### Added

- Initial read-only project scaffold: FastMCP server, environment-based configuration, async
  MISP client, JSONL audit logging for every MCP tool call, Docker support, and security /
  configuration documentation.
- Five initial analyst-oriented MISP workflow tools: `search_ioc`, `investigate_ioc`,
  `summarize_event`, `check_warninglists`, `generate_ioc_report`.
- Deterministic investigation scoring, verdict/confidence calculation, related-IOC extraction,
  context extraction, and recommendations for `investigate_ioc` and `generate_ioc_report`, with
  a stabilized public output schema.
- Five additional event-intelligence and pivoting tools: `pivot_ioc`, `find_related_iocs`,
  `extract_event_iocs`, `explain_event_context`, `find_events_by_tag`.
- Mocked test coverage for all 10 MCP tools. No live MISP or write/admin functionality is
  implemented.
