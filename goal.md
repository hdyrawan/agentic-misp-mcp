# agentic-misp-mcp Goal

Build an agentic MCP server for MISP that helps security analysts investigate IOCs, pivot across related indicators, summarize MISP events, check warninglists, generate threat intelligence reports, and later perform controlled write actions with policy, approval, and audit logging.

This project is not a raw MISP API wrapper. It exposes analyst-oriented workflows through MCP tools.

Core principles:
1. Workflow-first, not endpoint-first.
2. Read-only by default.
3. Safe write mode later, guarded by policy and approval.
4. Audit every tool execution.
5. Docker-ready.
6. Suitable for SOC and enterprise environments.
