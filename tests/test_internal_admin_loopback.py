"""Regression tests for internal-tool administrative authorization."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from core.middleware import (
    INTERNAL_TOOL_HEADER,
    INTERNAL_TOOL_TOKEN,
    require_admin,
)


@pytest.mark.parametrize(
    "client_host",
    ["192.0.2.10", "198.51.100.20"],
)
def test_remote_internal_token_cannot_grant_admin(client_host):
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/admin-test",
        "headers": [
            (
                INTERNAL_TOOL_HEADER.lower().encode(),
                INTERNAL_TOOL_TOKEN.encode(),
            )
        ],
        "client": (client_host, 54321),
        "server": ("127.0.0.1", 7000),
        "scheme": "http",
        "app": SimpleNamespace(
            state=SimpleNamespace(auth_manager=None)
        ),
    }

    request = Request(scope)

    with pytest.raises(HTTPException) as exc:
        require_admin(request)

    assert exc.value.status_code == 403


@pytest.mark.parametrize(
    "client_host,token_valid,proxy_header,expected_allowed",
    [
        ("127.0.0.1", True, False, True),
        ("::1", True, False, True),
        ("127.0.0.1", False, False, False),
        ("192.0.2.10", True, False, False),
        ("127.0.0.1", True, True, False),
        ("::1", True, True, False),
        ("127.0.0.1", True, "cf-connecting-ip", False),
        ("127.0.0.1", True, "cf-ray", False),
        ("127.0.0.1", True, "cf-visitor", False),
    ],
)
def test_internal_token_authorization_matrix(
    client_host, token_valid, proxy_header, expected_allowed
):
    headers = [
        (
            INTERNAL_TOOL_HEADER.lower().encode(),
            (
                INTERNAL_TOOL_TOKEN if token_valid else "invalid-token"
            ).encode(),
        )
    ]

    if proxy_header:
        header_name = proxy_header if isinstance(proxy_header, str) else "x-forwarded-for"
        headers.append((header_name.encode(), b"192.0.2.10"))

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/admin-test",
        "headers": headers,
        "client": (client_host, 54321),
        "server": ("127.0.0.1", 7000),
        "scheme": "http",
        "app": SimpleNamespace(
            state=SimpleNamespace(auth_manager=None)
        ),
    }

    request = Request(scope)

    if expected_allowed:
        assert require_admin(request) is None
    else:
        with pytest.raises(HTTPException) as exc:
            require_admin(request)
        assert exc.value.status_code == 403