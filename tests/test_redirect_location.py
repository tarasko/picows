from http import HTTPStatus

import pytest
from multidict import CIMultiDict

import picows
from picows import WSUpgradeResponse
from picows.api import _maybe_handle_redirect
from picows.url import parse_url
from tests.utils import AsyncClient, ServerEchoListener, ServerAsyncContext, ClientAsyncContext, get_server_port


async def test_redirect_location():
    exc = picows.WSUpgradeFailure("initial redirect")
    parsed_url = parse_url("ws://test_login:test_pws@my.domain.org/ws?param=val")
    assert not parsed_url.is_secure

    # Test empty response in exception
    with pytest.raises(picows.WSUpgradeFailure, match="initial redirect"):
        _maybe_handle_redirect(exc, parsed_url, 1)

    response = WSUpgradeResponse()
    response.version = b"HTTP/1.1"
    response.status = HTTPStatus.MOVED_PERMANENTLY
    response.headers = CIMultiDict()
    response.body = None

    exc.response = response

    # Test no Location header
    with pytest.raises(picows.WSUpgradeFailure, match="without Location header"):
        _maybe_handle_redirect(exc, parsed_url, 1)

    response.headers["Location"] = "/new_rel_path"

    # Check that redirect are done when max_redirects=0
    with pytest.raises(picows.WSUpgradeFailure, match="initial redirect"):
        _maybe_handle_redirect(exc, parsed_url, 0)

    new_parsed_url = _maybe_handle_redirect(exc, parsed_url, 1)
    assert new_parsed_url.url == "ws://test_login:test_pws@my.domain.org/new_rel_path"

    # Rel path completely replaces previous path
    # This is how urllib.parse.urljoin behaves. But I wonder if it is according to RFC?
    response.headers["Location"] = "new_rel_path"
    new_parsed_url = _maybe_handle_redirect(exc, parsed_url, 1)
    assert new_parsed_url.url == "ws://test_login:test_pws@my.domain.org/new_rel_path"

    response.headers["Location"] = "new_rel_path?param=val2"
    new_parsed_url = _maybe_handle_redirect(exc, parsed_url, 1)
    assert new_parsed_url.url == "ws://test_login:test_pws@my.domain.org/new_rel_path?param=val2"

    # Test abs location
    response.headers["Location"] = "ws://my.domain.org:8080/"
    new_parsed_url = _maybe_handle_redirect(exc, parsed_url, 1)
    assert new_parsed_url.url == "ws://my.domain.org:8080/"

    # Test TLS upgrade
    response.headers["Location"] = "wss://my.domain.org:8080/"
    new_parsed_url = _maybe_handle_redirect(exc, parsed_url, 1)
    assert new_parsed_url.url == "wss://my.domain.org:8080/"
    assert new_parsed_url.is_secure

    # Test TLS downgrade
    parsed_url = parse_url("wss://my.domain.org/ws?param=val")
    assert parsed_url.is_secure
    response.headers["Location"] = "ws://my.domain.org:8080/"

    with pytest.raises(picows.WSUpgradeFailure, match="non-secure URL"):
        _maybe_handle_redirect(exc, parsed_url, 1)

