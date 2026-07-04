from __future__ import annotations

from agentic_misp_mcp.openapi.classifier import classify_endpoint


def test_classify_read_endpoint():
    result = classify_endpoint(
        path="/attributes/restSearch",
        method="POST",
        operation_id="restSearchAttributes",
        summary="Search MISP attributes",
        tags=["Attributes"],
    )

    assert result.classification == "read"
    assert result.risk_level == "low"
    assert result.approval_required is False
    assert result.recommended_role == "read_only"


def test_classify_write_endpoint():
    result = classify_endpoint(
        path="/attributes/add/{eventId}",
        method="POST",
        operation_id="addAttribute",
        summary="Add an attribute to an event",
        tags=["Attributes"],
    )

    assert result.classification == "write"
    assert result.risk_level == "medium"
    assert result.approval_required is True
    assert result.recommended_role == "analyst_write"


def test_classify_write_delete_is_critical_risk():
    result = classify_endpoint(
        path="/attributes/delete/{id}",
        method="DELETE",
        operation_id="deleteAttribute",
        summary="Delete an attribute",
        tags=["Attributes"],
    )

    assert result.classification == "write"
    assert result.risk_level == "critical"
    assert result.approval_required is True


def test_classify_admin_endpoint():
    result = classify_endpoint(
        path="/admin/users/edit/{id}",
        method="POST",
        operation_id="editUser",
        summary="Edit a MISP user",
        tags=["Users"],
    )

    assert result.classification == "admin"
    assert result.risk_level == "high"
    assert result.approval_required is True
    assert result.recommended_role == "admin"


def test_classify_admin_auth_key_is_critical_risk():
    result = classify_endpoint(
        path="/auth_keys/index",
        method="GET",
        operation_id="listAuthKeys",
        summary="List authentication keys",
        tags=["AuthKeys"],
    )

    assert result.classification == "admin"
    assert result.risk_level == "critical"


def test_classify_sync_endpoint():
    result = classify_endpoint(
        path="/servers/pull/{id}",
        method="POST",
        operation_id="pullServer",
        summary="Pull events from a remote MISP server",
        tags=["Servers"],
    )

    assert result.classification == "sync"
    assert result.approval_required is True
    assert result.recommended_role == "curator"


def test_classify_dangerous_endpoint():
    result = classify_endpoint(
        path="/servers/restartWorkers",
        method="POST",
        operation_id="restartWorkers",
        summary="Restart background workers",
        tags=["Servers"],
    )

    assert result.classification == "dangerous"
    assert result.risk_level == "critical"
    assert result.approval_required is True


def test_classify_unknown_endpoint_is_not_guessed():
    result = classify_endpoint(
        path="/xyz/{id}",
        method="OPTIONS",
        operation_id=None,
        summary=None,
        tags=[],
    )

    assert result.classification == "unknown"
    assert result.risk_level == "unknown"
    assert result.approval_required is False
    assert result.recommended_role == "unknown"
