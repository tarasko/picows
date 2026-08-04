import asyncio

import pytest

from picows import websockets
from tests.utils import WSServer


async def test_ping_returns_waiter():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            pong_waiter = await ws.ping(b"abcd")
            latency = await asyncio.wait_for(pong_waiter, 1.0)
            assert latency >= 0


async def test_ping_accepts_byteslike_payloads():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            pong_waiter = await ws.ping(bytearray(b"abcd"))
            await asyncio.wait_for(pong_waiter, 1.0)
            pong_waiter = await ws.ping(memoryview(b"efgh"))
            await asyncio.wait_for(pong_waiter, 1.0)


async def test_pong_accepts_byteslike_payloads():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            await ws.pong(bytearray(b"abcd"))
            await ws.pong(memoryview(b"efgh"))


async def test_ping_default_duplicate_and_invalid_payloads():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            default_waiter = await ws.ping()
            await asyncio.wait_for(default_waiter, 1.0)

            waiter = await ws.ping("same")
            with pytest.raises(websockets.ConcurrencyError, match="same data"):
                await ws.ping(b"same")
            await asyncio.wait_for(waiter, 1.0)

            with pytest.raises(TypeError, match="ping payload"):
                await ws.ping(object())  # type: ignore[arg-type]


async def test_keepalive_loop_without_ping_timeout_sends_default_pings():
    async with WSServer(enable_auto_pong=True) as server:
        async with websockets.connect(
            server.url,
            compression=None,
            ping_interval=0.01,
            ping_timeout=None,
        ) as ws:
            await asyncio.sleep(0.03)
            assert ws.latency >= 0


async def test_keepalive_loop_with_ping_timeout_observes_pong():
    async with WSServer(enable_auto_pong=True) as server:
        async with websockets.connect(
            server.url,
            compression=None,
            ping_interval=0.01,
            ping_timeout=1.0,
        ) as ws:
            await asyncio.sleep(0.03)
            assert ws.latency >= 0


async def test_ping_and_pong_after_close_raise_connection_closed():
    async with WSServer() as server:
        ws = await websockets.connect(server.url, compression=None, ping_interval=None)
        await ws.close()

        with pytest.raises(websockets.ConnectionClosedOK):
            await ws.ping()
        with pytest.raises(websockets.ConnectionClosedOK):
            await ws.pong()
