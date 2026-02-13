from contextlib import asynccontextmanager

import anyio
import pytest
from tiny_proxy import HttpProxyHandler, Socks4ProxyHandler, Socks5ProxyHandler

import picows
from tests.utils import ClientAsyncContext, ClientMsgQueue, \
    create_client_ssl_context, echo_server


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
async def _proxy_context(proxy_type: str):
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


@pytest.mark.parametrize("proxy_type", ["http", "http_auth", "socks4", "socks5"])
async def test_proxy_connect_and_echo(echo_server, proxy_type: str):
    client_ssl_ctx = create_client_ssl_context()
    async with _proxy_context(proxy_type) as proxy_url:
        async with ClientAsyncContext(ClientMsgQueue, echo_server, ssl_context=client_ssl_ctx, proxy=proxy_url) as (transport, listener):
            transport.send(picows.WSMsgType.BINARY, b"hello over proxy")
            frame = await listener.get_message()
            assert frame.msg_type == picows.WSMsgType.BINARY
            assert frame.payload_as_bytes == b"hello over proxy"
