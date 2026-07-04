from __future__ import annotations

import pytest

from agentic_misp_mcp.cli import main


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 0
    assert "--transport" in capsys.readouterr().out


def test_cli_requires_known_transport():
    with pytest.raises(SystemExit) as exc:
        main(["--transport", "bad"])

    assert exc.value.code == 2
