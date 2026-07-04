from __future__ import annotations

import argparse
import sys

from pydantic import ValidationError

from agentic_misp_mcp import __version__
from agentic_misp_mcp.server import run_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentic-misp-mcp",
        description="Agentic MCP server for analyst-oriented MISP workflows.",
    )
    parser.add_argument("--version", action="version", version=f"agentic-misp-mcp {__version__}")
    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="MCP transport. stdio is the primary supported v0.1 transport.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        run_server(transport=args.transport)
    except ValidationError as exc:
        parser.exit(2, f"Configuration error: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
