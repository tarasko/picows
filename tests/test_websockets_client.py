import asyncio
import socket
from typing import Optional

import pytest
from multidict import CIMultiDict

import picows
from picows import websockets
from picows.websockets.asyncio.client import _process_proxy
from picows.websockets.asyncio.connection import process_exception
from picows.websockets.asyncio.utils import normalize_watermarks, resolve_logger
from tests.utils import ServerEchoListener, WSServer


def test_client_private_option_helpers():
    assert _process_proxy(None, False) is None
    assert _process_proxy("http://127.0.0.1:8080", False) == "http://127.0.0.1:8080"
    with pytest.raises(websockets.InvalidProxy):
        _process_proxy(123, False)  # type: ignore[arg-type]

    assert normalize_watermarks(None) == (0, 0)
    assert normalize_watermarks((None, 1)) == (0, 0)
    assert normalize_watermarks((8, None)) == (8, 2)
    assert resolve_logger("picows.test", "websockets.client").name == "picows.test"
    assert resolve_logger(None, "websockets.client").name == "websockets.client"


async def test_client_connection_starts_in_connecting_state():
    connection = websockets.ClientConnection(
        request=websockets.Request("/", CIMultiDict()),
        response=websockets.Response(101, "Switching Protocols", CIMultiDict(), b""),
        subprotocol=None,
        permessage_deflate=None,
        ping_interval=20,
        ping_timeout=20,
        close_timeout=10,
        max_queue=16,
        write_limit=32768,
        max_message_size=1024 * 1024,
        max_frame_size=1024 * 1024,
        logger=None,
    )

    assert connection.state is websockets.State.CONNECTING
    assert connection.open is False
    assert connection.closed is False


async def test_connect_await_style_and_socket_options():
    async with WSServer() as server:
        ws = await websockets.connect(server.url, compression=None, ping_interval=None)
        try:
            assert ws.state is websockets.State.OPEN
            assert ws.open is True
            assert ws.local_address[0] == "127.0.0.1"
            assert ws.remote_address[0] == "127.0.0.1"
            assert ws.latency == 0
            assert ws.subprotocol is None
            assert ws.close_code is None
            assert ws.close_reason is None
            await ws.send("awaited")
            assert await ws.recv() == "awaited"
        finally:
            await ws.close()

        sock = socket.create_connection((server.host, server.port))
        ws = await websockets.connect(server.url, compression=None, ping_interval=None, sock=sock)
        try:
            await ws.send(b"sock")
            assert await ws.recv() == b"sock"
        finally:
            await ws.close()

        async with websockets.connect(
            "ws://example.invalid/",
            compression=None,
            ping_interval=None,
            proxy=None,
            host=server.host,
            port=server.port,
        ) as ws:
            await ws.send("override")
            assert await ws.recv() == "override"


async def test_connect_rejects_conflicting_and_invalid_socket_options():
    async with WSServer() as server:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(TypeError, match="cannot pass both sock and socket_factory"):
                await websockets.connect(server.url, compression=None, sock=sock, socket_factory=lambda _: None)
        finally:
            sock.close()

        with pytest.raises(TypeError, match="sock must be a socket.socket instance"):
            await websockets.connect(server.url, compression=None, sock=object())

        with pytest.raises(TypeError, match="cannot pass both host/port override and socket_factory"):
            await websockets.connect(
                server.url,
                compression=None,
                host=server.host,
                socket_factory=lambda _: None,
            )


async def test_connect_rejects_invalid_ssl_options_before_network():
    with pytest.raises(NotImplementedError, match="ssl=False"):
        await websockets.connect("wss://example.com/", compression=None, ssl=False)
    with pytest.raises(TypeError, match="ssl must be"):
        await websockets.connect("wss://example.com/", compression=None, ssl=object())


def test_process_exception_retries_transient_failures():
    assert process_exception(EOFError()) is None
    assert process_exception(OSError()) is None
    assert process_exception(asyncio.TimeoutError()) is None

    response = websockets.Response(503, "Service Unavailable", CIMultiDict(), b"")
    assert process_exception(websockets.InvalidStatus(response)) is None

    error = RuntimeError("boom")
    assert process_exception(error) is error


async def test_connect_async_iterator_retries_then_succeeds():
    attempts = 0

    def process_exception(exc: Exception) -> Optional[Exception]:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return None
        return exc

    connector = websockets.connect(
        "ws://127.0.0.1:1/",
        compression=None,
        open_timeout=0.01,
        process_exception=process_exception,
    )
    connector._backoff = 0
    with pytest.raises(OSError):
        async for _ws in connector:
            pass
    assert attempts == 2


def test_connect_rejects_create_connection():
    with pytest.raises(NotImplementedError):
        websockets.connect("ws://example.com", create_connection=websockets.ClientConnection)


async def test_connection_context_manager_and_close_timeout_none():
    async with WSServer() as server:
        ws = await websockets.connect(server.url, compression=None, ping_interval=None, close_timeout=None)
        async with ws:
            await ws.send("context")
            assert await ws.recv() == "context"
        assert ws.state is websockets.State.CLOSED
        assert ws.open is False
        assert ws.closed is True


class IgnoreCloseListener(ServerEchoListener):
    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        if frame.msg_type == picows.WSMsgType.CLOSE:
            return
        super().on_ws_frame(transport, frame)


async def test_close_timeout_disconnects_when_peer_ignores_close():
    async with WSServer(lambda _: IgnoreCloseListener()) as server:
        ws = await websockets.connect(
            server.url,
            compression=None,
            ping_interval=None,
            close_timeout=0.01,
        )
        await ws.close()
        assert ws.state is websockets.State.CLOSED
        assert ws.close_code == 1000
        assert ws.close_reason == ""
