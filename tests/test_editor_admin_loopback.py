"""Regression tests for editor-agent internal administrative authorization."""

from types import SimpleNamespace

import pytest
from starlette.requests import Request

from core.middleware import INTERNAL_TOOL_HEADER, INTERNAL_TOOL_TOKEN
from routes.editor_agent_routes import _is_admin


@pytest.mark.parametrize(
    "client_host,forwarded_header,expected_allowed",
    [
        ("192.0.2.10", None, False),
        ("198.51.100.20", None, False),
        ("127.0.0.1", None, True),
        ("::1", None, True),
        ("127.0.0.1", "x-forwarded-for", False),
        ("127.0.0.1", "cf-connecting-ip", False),
        ("127.0.0.1", "cf-ray", False),
        ("127.0.0.1", "cf-visitor", False),
    ],
)
def test_editor_internal_token_requires_direct_loopback(
    monkeypatch, client_host, forwarded_header, expected_allowed
):
    monkeypatch.setattr("src.auth_helpers._auth_disabled", lambda: False)

    headers = [
        (
            INTERNAL_TOOL_HEADER.lower().encode(),
            INTERNAL_TOOL_TOKEN.encode(),
        )
    ]

    if forwarded_header:
        headers.append((forwarded_header.encode(), b"192.0.2.10"))

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/editor-agent/test",
        "headers": headers,
        "client": (client_host, 54321),
        "server": ("127.0.0.1", 7000),
        "scheme": "http",
        "app": SimpleNamespace(
            state=SimpleNamespace(auth_manager=None)
        ),
    }

    request = Request(scope)

    assert _is_admin(request) is expected_allowed


def test_editor_authenticated_remote_admin_session(monkeypatch):
    """A validated administrator session must not require loopback."""
    monkeypatch.setattr("src.auth_helpers._auth_disabled", lambda: False)

    auth_manager = SimpleNamespace(
        is_configured=True,
        is_admin=lambda username: username == "test-admin",
    )

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/editor-agent/test",
        "headers": [],
        "client": ("192.0.2.10", 54321),
        "server": ("127.0.0.1", 7000),
        "scheme": "http",
        "app": SimpleNamespace(
            state=SimpleNamespace(auth_manager=auth_manager)
        ),
    }

    request = Request(scope)
    request.state.current_user = "test-admin"

    assert _is_admin(request) is True
