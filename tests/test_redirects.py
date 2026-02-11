from http import HTTPStatus

import pytest
from multidict import CIMultiDict

import picows
from picows import WSUpgradeResponse
from picows.api import _maybe_handle_redirect
from picows.url import parse_url
from tests.utils import ClientMsgQueue, ServerEchoListener, ServerAsyncContext, ClientAsyncContext, get_server_port


async def test_redirect_chain():
    def final_listener_factory(r):
        return ServerEchoListener()

    final_server = await picows.ws_create_server(final_listener_factory, "127.0.0.1", 0)

    def redirect_1_listener_factory(r):
        resp = picows.WSUpgradeResponse.create_redirect_response(
            HTTPStatus.MOVED_PERMANENTLY,
            f"ws://127.0.0.1:{get_server_port(final_server)}"
        )
        return picows.WSUpgradeResponseWithListener(resp, None)

    redirect_1_server = await picows.ws_create_server(redirect_1_listener_factory, "127.0.0.1", 0)

    def redirect_2_listener_factory(r):
        resp = picows.WSUpgradeResponse.create_redirect_response(
            HTTPStatus.MOVED_PERMANENTLY,
            f"ws://127.0.0.1:{get_server_port(redirect_1_server)}"
        )
        return picows.WSUpgradeResponseWithListener(resp, None)

    redirect_2_server = await picows.ws_create_server(redirect_2_listener_factory, "127.0.0.1", 0)

    url = f"ws://test_login:test_pwd@127.0.0.1:{get_server_port(redirect_2_server)}"

    async with ServerAsyncContext(final_server), ServerAsyncContext(redirect_1_server), ServerAsyncContext(redirect_2_server):
        listener: ClientMsgQueue
        async with ClientAsyncContext(ClientMsgQueue, url) as (transport, listener):
            transport.send(picows.WSMsgType.TEXT, b"hello")
            msg = await listener.get_message()
            assert msg.payload_as_ascii_text == "hello"

        with pytest.raises(picows.WSError, match="status 101"):
            await picows.ws_connect(ClientMsgQueue, url, max_redirects=0)

        with pytest.raises(picows.WSError, match="status 101"):
            await picows.ws_connect(ClientMsgQueue, url, max_redirects=1)


async def test_redirect_location():
    exc = picows.WSError("initial redirect")
    parsed_url = parse_url("ws://test_login:test_pws@my.domain.org/ws?param=val")
    assert not parsed_url.secure

    # Test empty response in exception
    with pytest.raises(picows.WSError, match="initial redirect"):
        _maybe_handle_redirect(exc, parsed_url, 1)

    response = WSUpgradeResponse()
    response.version = b"HTTP/1.1"
    response.status = HTTPStatus.MOVED_PERMANENTLY
    response.headers = CIMultiDict()
    response.body = None

    exc.response = response

    # Test no Location header
    with pytest.raises(picows.WSError, match="without Location header"):
        _maybe_handle_redirect(exc, parsed_url, 1)

    response.headers["Location"] = "/new_rel_path"

    # Check that redirect are done when max_redirects=0
    with pytest.raises(picows.WSError, match="initial redirect"):
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
    assert new_parsed_url.secure

    # Test TLS downgrade
    parsed_url = parse_url("wss://my.domain.org/ws?param=val")
    assert parsed_url.secure
    response.headers["Location"] = "ws://my.domain.org:8080/"

    with pytest.raises(picows.WSError, match="non-secure URL"):
        _maybe_handle_redirect(exc, parsed_url, 1)

