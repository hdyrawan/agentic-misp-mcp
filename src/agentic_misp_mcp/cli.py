from __future__ import annotations

import argparse
import sys

from pydantic import ValidationError

from agentic_misp_mcp import __version__
from agentic_misp_mcp.cli_approvals import add_approvals_subparser, handle_approvals_command
from agentic_misp_mcp.config_check import check_configuration, format_validation_error_lines
from agentic_misp_mcp.config_doctor import run_config_doctor_cli
from agentic_misp_mcp.openapi import generate_markdown_inventory_file
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

    config_parser = subparsers.add_parser(
        "config",
        help="Configuration operational-readiness commands.",
    )
    config_subparsers = config_parser.add_subparsers(dest="config_command", required=True)
    config_subparsers.add_parser(
        "doctor",
        help=(
            "Validate operational-readiness configuration combinations (write/approval mode, "
            "publish role, approval store and audit log safety, allowlists, TTL, temp paths, "
            "and leftover approval tokens). Outputs PASS/WARN/FAIL, redacts secrets, and exits "
            "nonzero on any FAIL."
        ),
    )

    add_approvals_subparser(subparsers)

    openapi_inventory_parser = subparsers.add_parser(
        "openapi-inventory",
        help=(
            "Classify a MISP OpenAPI spec into a read/write/admin/sync/dangerous risk "
            "inventory. Planning only; does not expose any MISP API endpoint as a tool."
        ),
    )
    openapi_inventory_parser.add_argument(
        "--input", required=True, help="Path to a MISP OpenAPI spec in JSON format."
    )
    openapi_inventory_parser.add_argument(
        "--output",
        default="docs/openapi-inventory.md",
        help="Path to write the generated Markdown inventory (default: docs/openapi-inventory.md).",
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

    if args.command == "config":
        if args.config_command == "doctor":
            return run_config_doctor_cli()
        parser.exit(2, "Unknown config command\n")

    if args.command == "approvals":
        return handle_approvals_command(args)

    if args.command == "openapi-inventory":
        try:
            count, output_path = generate_markdown_inventory_file(
                input_path=args.input, output_path=args.output
            )
        except (OSError, ValueError) as exc:
            parser.exit(2, f"OpenAPI inventory error: {exc}\n")
        sys.stdout.write(f"Wrote OpenAPI inventory for {count} endpoint(s) to {output_path}\n")
        return 0

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
