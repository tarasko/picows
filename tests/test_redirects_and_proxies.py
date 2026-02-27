import socket
import ssl
from contextlib import asynccontextmanager
from http import HTTPStatus
from logging import getLogger
from typing import Optional

import anyio
import pytest
from tiny_proxy import HttpProxyHandler, Socks4ProxyHandler, Socks5ProxyHandler

import picows
from picows.url import parse_url
from tests.utils import ClientAsyncContext, AsyncClient, \
    create_client_ssl_context, echo_server, multiloop_event_loop_policy, \
    ServerAsyncContext

event_loop_policy = multiloop_event_loop_policy()

_logger = getLogger(__name__)

def _create_proxy_handler(proxy_type: str):
    if proxy_type == "http":
        return HttpProxyHandler()
    if proxy_type == "http_auth":
        return HttpProxyHandler(username="user", password="password")
    if proxy_type == "socks4":
        return Socks4ProxyHandler()
    if proxy_type == "socks5":
        return Socks5ProxyHandler(username="user", password="password")

    raise RuntimeError(f"unknown proxy_type={proxy_type}")


_proxy_url_templates = {
    "http": "http://127.0.0.1:{port}",
    "http_auth": "http://user:password@127.0.0.1:{port}",
    "socks4": "socks4://127.0.0.1:{port}",
    "socks5": "socks5://user:password@127.0.0.1:{port}"
}

@asynccontextmanager
async def ProxyServer(proxy_type: str):
    if proxy_type == "direct":
        yield None
        return

    url_template = _proxy_url_templates[proxy_type]
    handler = _create_proxy_handler(proxy_type)
    listener = await anyio.create_tcp_listener(local_host="127.0.0.1")

    task_group = anyio.create_task_group()
    await task_group.__aenter__()
    task_group.start_soon(listener.serve, handler.handle)

    try:
        proxy_port = listener.listeners[0].extra(anyio.abc.SocketAttribute.local_port)
        yield url_template.format(port=proxy_port)
    finally:
        task_group.cancel_scope.cancel()
        await task_group.__aexit__(None, None, None)
        await listener.aclose()


@pytest.fixture()
async def redirect_server_1(echo_server):
    def listener_factory(r):
        resp = picows.WSUpgradeResponse.create_redirect_response(
            HTTPStatus.MOVED_PERMANENTLY,
            echo_server
        )
        return picows.WSUpgradeResponseWithListener(resp, None)

    server = await picows.ws_create_server(listener_factory, "127.0.0.1", 0)
    async with ServerAsyncContext(server) as server_urls:
        yield server_urls.tcp_url


@pytest.fixture()
async def redirect_server_2(redirect_server_1):
    def listener_factory(r):
        resp = picows.WSUpgradeResponse.create_redirect_response(
            HTTPStatus.MOVED_PERMANENTLY,
            redirect_server_1
        )
        return picows.WSUpgradeResponseWithListener(resp, None)

    server = await picows.ws_create_server(listener_factory, "127.0.0.1", 0)
    async with ServerAsyncContext(server) as server_urls:
        yield server_urls.tcp_url


@pytest.mark.parametrize("proxy_type", ["direct", "http", "http_auth", "socks4", "socks5"])
@pytest.mark.parametrize("custom_sock", ["none", "new", "connected"])
@pytest.mark.parametrize("cb_type", ["cb", "awaitable"])
async def test_redirect_through_proxy(redirect_server_2, proxy_type: str, custom_sock: str, cb_type: str):
    # This is an absolute masterpiece! Best test I wrote ever!
    #
    # This test under all possible loops (asyncio, uvloop) goes through
    # all possible proxies kinds, including no proxy at all, follows 2 redirects,
    # each redirect is connected again through the current proxy, and finally reach
    # echo server, send request and validate response.
    #
    # God bless pytest!
    client_ssl_ctx = create_client_ssl_context()

    last_socket = None

    async with ProxyServer(proxy_type) as proxy_url:
        def socket_factory_cb(parsed_url) -> Optional[socket.socket]:
            nonlocal last_socket

            if custom_sock == "none":
                last_socket = None
                return last_socket
            elif custom_sock == "new":
                last_socket = socket.socket(socket.AF_INET)
                return last_socket
            else:
                last_socket = socket.socket(socket.AF_INET)
                last_socket.connect((parsed_url.host, parsed_url.port))
                return last_socket

        async def socket_factory_awaitable(parsed_url) -> Optional[socket.socket]:
            return socket_factory_cb(parsed_url)

        socket_factory = socket_factory_cb if cb_type == "cb" else socket_factory_awaitable

        async with ClientAsyncContext(AsyncClient, redirect_server_2, ssl_context=client_ssl_ctx, proxy=proxy_url, socket_factory=socket_factory) as (transport, listener):
            # Check that we are using the same socket that was produced by socket_factory
            if last_socket is not None:
                sock = transport.underlying_transport.get_extra_info('socket')
                assert last_socket.getsockname() == sock.getsockname()
                # Check that we are connected to the proxy
                if proxy_url is not None:
                    pu = parse_url(proxy_url, False)
                    peer = sock.getpeername()
                    assert pu.host == peer[0] and pu.port == peer[1]

            transport.send(picows.WSMsgType.BINARY, b"hello over proxy")
            frame = await listener.get_message()
            assert frame.msg_type == picows.WSMsgType.BINARY
            assert frame.payload_as_bytes == b"hello over proxy"

        with pytest.raises(picows.WSError, match="status 101"):
            await picows.ws_connect(AsyncClient, redirect_server_2, max_redirects=0, proxy=proxy_url)

        with pytest.raises(picows.WSError, match="status 101"):
            await picows.ws_connect(AsyncClient, redirect_server_2, max_redirects=1, proxy=proxy_url)


@pytest.mark.parametrize("proxy_type", ["direct", "http", "socks4", "socks5"])
async def test_proxy_dns_resolution(proxy_type):
    client_ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    async with ProxyServer(proxy_type) as proxy_url:
        async with ClientAsyncContext(AsyncClient, "wss://echo.websocket.org", ssl_context=client_ssl_ctx, proxy=proxy_url) as (transport, listener):
            frame = await listener.get_message()
            _logger.debug("Welcome frame from echo.websocket.org: %s", frame.payload_as_ascii_text)
            transport.send(picows.WSMsgType.BINARY, b"hello over proxy")
            frame = await listener.get_message()
            assert frame.msg_type == picows.WSMsgType.BINARY
            assert frame.payload_as_bytes == b"hello over proxy"
