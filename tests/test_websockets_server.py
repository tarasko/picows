import asyncio
import sys

import pytest

from picows import websockets


async def test_serve_echo_roundtrip():
    async def handler(ws: websockets.ServerConnection) -> None:
        assert ws.request.path == "/"
        assert ws.response.status_code == 101
        message = await ws.recv()
        await ws.send(message)

    async with websockets.serve(handler, "127.0.0.1", 0, compression=None) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None) as ws:
            await ws.send("hello")
            assert await ws.recv() == "hello"


async def test_serve_rejects_create_connection():
    async def handler(ws: websockets.ServerConnection) -> None:
        raise AssertionError("handler must not be called")

    with pytest.raises(NotImplementedError):
        await websockets.serve(
            handler,
            "127.0.0.1",
            0,
            compression=None,
            create_connection=websockets.ServerConnection,
        )


async def test_broadcast_sends_to_open_connections():
    connections: list[websockets.ServerConnection] = []

    async def handler(ws: websockets.ServerConnection) -> None:
        connections.append(ws)
        await ws.wait_closed()

    async with websockets.serve(handler, "127.0.0.1", 0, compression=None) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None) as ws1:
            async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None) as ws2:
                while len(connections) < 2:
                    await asyncio.sleep(0)
                websockets.broadcast(connections, "hi")
                assert await ws1.recv() == "hi"
                assert await ws2.recv() == "hi"


def test_broadcast_validation_and_exception_group():
    with pytest.raises(TypeError, match="data must be str or bytes"):
        websockets.broadcast([], object())  # type: ignore[arg-type]

    if sys.version_info[:2] < (3, 11):
        with pytest.raises(ValueError, match="requires at least Python 3.11"):
            websockets.broadcast([], "hello", raise_exceptions=True)
        return

    class BrokenConnection:
        state = websockets.State.OPEN
        _send_in_progress = False

        def _encode_and_send(self, _msg_type, _message, _fin):
            raise RuntimeError("broken")

    with pytest.raises(ExceptionGroup) as exc_info:
        websockets.broadcast([BrokenConnection()], "hello", raise_exceptions=True)  # type: ignore[list-item]
    assert len(exc_info.value.exceptions) == 1


async def test_server_connections_tracks_open_connections():
    connected = asyncio.Event()

    async def handler(ws: websockets.ServerConnection) -> None:
        connected.set()
        await ws.wait_closed()

    async with websockets.serve(handler, "127.0.0.1", 0, compression=None) as server:
        port = server.sockets[0].getsockname()[1]
        assert server.connections == set()
        async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None):
            await connected.wait()
            assert len(server.connections) == 1
        await asyncio.sleep(0)
        assert server.connections == set()


async def test_handler_exception_closes_connection_with_internal_error():
    async def handler(ws: websockets.ServerConnection) -> None:
        raise RuntimeError("boom")

    async with websockets.serve(handler, "127.0.0.1", 0, compression=None) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()
            assert ws.close_code == 1011


async def test_tuple_max_size_applies_message_limit_to_server_wrapper():
    closed_by_limit = asyncio.Event()

    async def handler(ws: websockets.ServerConnection) -> None:
        with pytest.raises(websockets.ConnectionClosedError):
            await ws.recv()
        closed_by_limit.set()

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        max_size=(4, 10),
    ) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(
            f"ws://127.0.0.1:{port}/",
            compression=None,
            ping_interval=None,
        ) as ws:
            await ws.send([b"he", b"llo"])
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()
            await asyncio.wait_for(closed_by_limit.wait(), 1)


async def test_tuple_max_size_applies_frame_limit_to_server_core():
    closed_by_limit = asyncio.Event()

    async def handler(ws: websockets.ServerConnection) -> None:
        with pytest.raises(websockets.ConnectionClosedError):
            await ws.recv()
        closed_by_limit.set()

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        max_size=(10, 2),
    ) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(
            f"ws://127.0.0.1:{port}/",
            compression=None,
            ping_interval=None,
        ) as ws:
            await ws.send("large")
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()
            await asyncio.wait_for(closed_by_limit.wait(), 1)


async def test_server_close_closes_existing_connections():
    started = asyncio.Event()

    async def handler(ws: websockets.ServerConnection) -> None:
        started.set()
        await ws.wait_closed()

    async with websockets.serve(handler, "127.0.0.1", 0, compression=None) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None) as ws:
            await started.wait()
            server.close(reason="bye")
            with pytest.raises(websockets.ConnectionClosedOK):
                await ws.recv()
            assert ws.close_code == 1001
            assert ws.close_reason == "bye"
        await server.wait_closed()


async def test_wait_closed_waits_for_handler_completion():
    started = asyncio.Event()
    finish = asyncio.Event()
    finished = asyncio.Event()

    async def handler(ws: websockets.ServerConnection) -> None:
        started.set()
        await finish.wait()
        finished.set()

    server = await websockets.serve(handler, "127.0.0.1", 0, compression=None)
    port = server.sockets[0].getsockname()[1]
    async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None):
        await started.wait()
        server.close(close_connections=False)
        waiter = asyncio.create_task(server.wait_closed())
        await asyncio.sleep(0)
        assert not waiter.done()
        finish.set()
        await waiter
        assert finished.is_set()


def test_route_requires_werkzeug():
    with pytest.raises((ImportError, NotImplementedError)):
        websockets.route(None)  # type: ignore[arg-type]
