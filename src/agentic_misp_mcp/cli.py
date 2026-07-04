from __future__ import annotations

import argparse
import sys

from pydantic import ValidationError

from agentic_misp_mcp import __version__
from agentic_misp_mcp.config_check import check_configuration, format_validation_error_lines
from agentic_misp_mcp.server import StartupConfigurationError, run_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentic-misp-mcp",
        description="Agentic MCP server for analyst-oriented MISP workflows.",
    )
    parser.add_argument("--version", action="version", version=f"agentic-misp-mcp {__version__}")

    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser(
        "config-check",
        help="Validate environment configuration without connecting to MISP.",
    )

    parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="MCP transport. stdio is the primary supported v0.1 transport.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP bind host for experimental --transport http mode.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="HTTP bind port for experimental --transport http mode.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "config-check":
        result = check_configuration()
        stream = sys.stdout if result.ok else sys.stderr
        stream.write(result.render())
        return 0 if result.ok else 2

    try:
        run_server(transport=args.transport, host=args.host, port=args.port)
    except ValidationError as exc:
        lines = "\n".join(format_validation_error_lines(exc))
        parser.exit(2, f"Configuration error:\n{lines}\n")
    except StartupConfigurationError as exc:
        parser.exit(2, f"Startup error: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
