import asyncio
import ssl
import sys
from contextlib import asynccontextmanager
from http import HTTPStatus
from logging import getLogger

import anyio
import pytest
from anyio.streams.tls import TLSListener
from tiny_proxy import HttpProxyHandler, Socks4ProxyHandler, Socks5ProxyHandler

import picows
import picows.api as picows_api
from tests.utils import ClientAsyncContext, AsyncClient, \
    create_client_ssl_context, echo_server, multiloop_event_loop_policy, \
    ServerAsyncContext, create_server_ssl_context

event_loop_policy = multiloop_event_loop_policy()

_logger = getLogger(__name__)

def _create_proxy_handler(proxy_type: str):
    if proxy_type == "http":
        return HttpProxyHandler()
    if proxy_type == "http_auth":
        return HttpProxyHandler(username="user", password="password")
    if proxy_type == "https":
        return HttpProxyHandler()
    if proxy_type == "https_auth":
        return HttpProxyHandler(username="user", password="password")
    if proxy_type == "socks4":
        return Socks4ProxyHandler()
    if proxy_type == "socks5":
        return Socks5ProxyHandler(username="user", password="password")

    raise RuntimeError(f"unknown proxy_type={proxy_type}")


_proxy_url_templates = {
    "http": "http://127.0.0.1:{port}",
    "http_auth": "http://user:password@127.0.0.1:{port}",
    "https": "https://127.0.0.1:{port}",
    "https_auth": "https://user:password@127.0.0.1:{port}",
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
    proxy_listener = TLSListener(listener, create_server_ssl_context()) if proxy_type.startswith("https") else listener

    task_group = anyio.create_task_group()
    await task_group.__aenter__()
    task_group.start_soon(proxy_listener.serve, handler.handle)

    try:
        proxy_port = listener.listeners[0].extra(anyio.abc.SocketAttribute.local_port)
        yield url_template.format(port=proxy_port)
    finally:
        task_group.cancel_scope.cancel()
        await task_group.__aexit__(None, None, None)
        await proxy_listener.aclose()


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


@pytest.mark.parametrize("proxy_type", ["direct", "socks4", "socks5", "http", "http_auth", "https", "https_auth"])
async def test_redirect_through_proxy(redirect_server_2, proxy_type: str):
    # This is an absolute masterpiece! Best test I wrote ever!
    #
    # This test under all possible loops (asyncio, uvloop) goes through
    # all possible proxies kinds, including no proxy at all, follows 2 redirects,
    # each redirect is connected again through the current proxy, and finally reach
    # echo server, send request and validate response.
    #
    # God bless pytest!

    is_https = proxy_type in ("https", "https_auth")
    is_asyncio_loop = isinstance(asyncio.get_event_loop_policy(), asyncio.DefaultEventLoopPolicy)

    if sys.version_info < (3, 11) and is_asyncio_loop and is_https:
        pytest.skip("HTTPS proxy using asyncio requires Python 3.11+")
        return

    client_ssl_ctx = create_client_ssl_context()
    proxy_ssl_ctx = create_client_ssl_context() if is_https else None

    async with ProxyServer(proxy_type) as proxy_url:
        async with ClientAsyncContext(AsyncClient, redirect_server_2, ssl_context=client_ssl_ctx, proxy=proxy_url, proxy_ssl_context=proxy_ssl_ctx) as (transport, listener):
            transport.send(picows.WSMsgType.BINARY, b"hello over proxy")
            frame = await listener.get_message(1.0)
            assert frame.msg_type == picows.WSMsgType.BINARY
            assert frame.payload_as_bytes == b"hello over proxy"

        with pytest.raises(picows.WSError, match="status 101"):
            await picows.ws_connect(AsyncClient, redirect_server_2, max_redirects=0, proxy=proxy_url, proxy_ssl_context=proxy_ssl_ctx)

        with pytest.raises(picows.WSError, match="status 101"):
            await picows.ws_connect(AsyncClient, redirect_server_2, max_redirects=1, proxy=proxy_url, proxy_ssl_context=proxy_ssl_ctx)


@pytest.mark.parametrize("proxy_type", ["socks4", "socks5", "http"])
@pytest.mark.skip(reason="echo server may respond with 429 (too many requests if we spam it a lot)")
async def test_proxy_dns_resolution(proxy_type):
    is_https = proxy_type in ("https", "https_auth")
    is_asyncio_loop = isinstance(asyncio.get_event_loop_policy(), asyncio.DefaultEventLoopPolicy)

    if sys.version_info < (3, 11) and is_asyncio_loop and is_https:
        pytest.skip("HTTPS proxy using asyncio requires Python 3.11+")
        return

    client_ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    proxy_ssl_ctx = create_client_ssl_context() if is_https else None

    async with ProxyServer(proxy_type) as proxy_url:
        async with ClientAsyncContext(AsyncClient, "wss://echo.websocket.org", ssl_context=client_ssl_ctx, proxy=proxy_url, proxy_ssl_context=proxy_ssl_ctx) as (transport, listener):
            frame = await listener.get_message()
            _logger.debug("Welcome frame from echo.websocket.org: %s", frame.payload_as_ascii_text)
            transport.send(picows.WSMsgType.BINARY, b"hello over proxy")
            frame = await listener.get_message()
            assert frame.msg_type == picows.WSMsgType.BINARY
            assert frame.payload_as_bytes == b"hello over proxy"

