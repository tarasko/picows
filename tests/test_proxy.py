import asyncio
import socket
from contextlib import asynccontextmanager, closing

import anyio
import pytest
from tiny_proxy import HttpProxyHandler, Socks4ProxyHandler, Socks5ProxyHandler

import picows
from tests.utils import ClientAsyncContext, ClientMsgQueue, ServerAsyncContext, ServerEchoListener


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


def _get_unused_tcp_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def _wait_until_proxy_accepts_connections(port: int):
    for _ in range(40):
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)

    raise RuntimeError(f"proxy server on port {port} did not start")


@asynccontextmanager
async def _proxy_context(proxy_type: str):
    proxy_port = _get_unused_tcp_port()
    handler = _create_proxy_handler(proxy_type)
    listener = await anyio.create_tcp_listener(local_host="127.0.0.1", local_port=proxy_port)

    task_group = anyio.create_task_group()
    await task_group.__aenter__()
    task_group.start_soon(listener.serve, handler.handle)

    try:
        await _wait_until_proxy_accepts_connections(proxy_port)
        yield proxy_port
    finally:
        task_group.cancel_scope.cancel()
        await task_group.__aexit__(None, None, None)
        await listener.aclose()


@pytest.mark.parametrize(
    ("proxy_type", "proxy_url_template"),
    [
        ("http", "http://127.0.0.1:{port}"),
        ("http_auth", "http://user:password@127.0.0.1:{port}"),
        ("socks4", "socks4://127.0.0.1:{port}"),
        ("socks5", "socks5://user:password@127.0.0.1:{port}"),
    ],
)
async def test_proxy_connect_and_echo(proxy_type: str, proxy_url_template: str):
    server = await picows.ws_create_server(lambda _: ServerEchoListener(), "127.0.0.1", 0)

    async with ServerAsyncContext(server) as server_ctx:
        async with _proxy_context(proxy_type) as proxy_port:
            proxy_url = proxy_url_template.format(port=proxy_port)
            async with ClientAsyncContext(ClientMsgQueue, server_ctx.plain_url, proxy=proxy_url) as (transport, listener):
                transport.send(picows.WSMsgType.BINARY, b"hello over proxy")
                frame = await listener.get_message()
                assert frame.msg_type == picows.WSMsgType.BINARY
                assert frame.payload_as_bytes == b"hello over proxy"
