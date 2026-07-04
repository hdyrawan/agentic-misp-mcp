from __future__ import annotations

import json

import pytest

from agentic_misp_mcp.openapi.inventory import (
    build_inventory,
    generate_markdown_inventory_file,
    load_openapi_spec,
    render_markdown_inventory,
)

MINIMAL_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "MISP", "version": "1.0.0"},
    "paths": {
        "/attributes/restSearch": {
            "post": {
                "operationId": "restSearchAttributes",
                "summary": "Search MISP attributes",
                "tags": ["Attributes"],
            }
        },
        "/attributes/add/{eventId}": {
            "post": {
                "operationId": "addAttribute",
                "summary": "Add an attribute to an event",
                "tags": ["Attributes"],
            }
        },
        "/admin/users/edit/{id}": {
            "post": {
                "operationId": "editUser",
                "summary": "Edit a MISP user",
                "tags": ["Users"],
            }
        },
        "/servers/pull/{id}": {
            "post": {
                "operationId": "pullServer",
                "summary": "Pull events from a remote MISP server",
                "tags": ["Servers"],
            }
        },
        "/xyz/{id}": {
            "options": {
                "summary": "Unclassifiable endpoint",
            }
        },
    },
}


def test_parse_minimal_openapi_fixture_produces_one_entry_per_operation():
    entries = build_inventory(MINIMAL_SPEC)

    assert len(entries) == 5
    paths = {entry.path for entry in entries}
    assert paths == {
        "/attributes/restSearch",
        "/attributes/add/{eventId}",
        "/admin/users/edit/{id}",
        "/servers/pull/{id}",
        "/xyz/{id}",
    }


def test_build_inventory_classifies_each_endpoint():
    entries = {entry.path: entry for entry in build_inventory(MINIMAL_SPEC)}

    assert entries["/attributes/restSearch"].classification == "read"
    assert entries["/attributes/add/{eventId}"].classification == "write"
    assert entries["/admin/users/edit/{id}"].classification == "admin"
    assert entries["/servers/pull/{id}"].classification == "sync"
    assert entries["/xyz/{id}"].classification == "unknown"


def test_build_inventory_ignores_non_path_or_non_operation_entries():
    spec = {
        "paths": {
            "/ok": {"get": {"summary": "fine"}},
            "/not-a-dict": "oops",
            "/mixed": {"get": {"summary": "fine"}, "parameters": ["not-an-operation"]},
        }
    }

    entries = build_inventory(spec)

    assert {entry.path for entry in entries} == {"/ok", "/mixed"}


def test_load_openapi_spec_rejects_invalid_json(tmp_path):
    bad_file = tmp_path / "spec.json"
    bad_file.write_text("not json", encoding="utf-8")

    with pytest.raises(ValueError, match="Could not parse"):
        load_openapi_spec(bad_file)


def test_load_openapi_spec_reads_valid_json(tmp_path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(MINIMAL_SPEC), encoding="utf-8")

    spec = load_openapi_spec(spec_file)

    assert spec["info"]["title"] == "MISP"


def test_render_markdown_inventory_includes_required_sections():
    entries = build_inventory(MINIMAL_SPEC)
    markdown = render_markdown_inventory(entries)

    assert markdown.startswith("# MISP OpenAPI Inventory")
    assert "Planning only" in markdown
    assert "does not expose any MISP API endpoint as an MCP tool" in markdown
    assert "Total endpoints: 5" in markdown
    for classification in ("read", "write", "admin", "sync", "dangerous", "unknown"):
        assert f"## {classification}" in markdown
    assert "/attributes/restSearch" in markdown
    assert "/admin/users/edit/{id}" in markdown


def test_render_markdown_inventory_handles_empty_entries():
    markdown = render_markdown_inventory([])

    assert "Total endpoints: 0" in markdown
    assert "No endpoints in this category." in markdown


def test_generate_markdown_inventory_file_writes_output(tmp_path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(MINIMAL_SPEC), encoding="utf-8")
    output_file = tmp_path / "nested" / "openapi-inventory.md"

    count, output_path = generate_markdown_inventory_file(
        input_path=spec_file, output_path=output_file
    )

    assert count == 5
    assert output_path == str(output_file)
    written = output_file.read_text(encoding="utf-8")
    assert "MISP OpenAPI Inventory" in written
