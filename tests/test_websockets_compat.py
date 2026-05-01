import asyncio

import pytest

from picows import websockets
from tests.utils import WSServer


async def test_connect_send_recv_text():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None) as ws:
            await ws.send("hello")
            reply = await ws.recv()
            assert reply == "hello"


async def test_connect_send_recv_binary():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None) as ws:
            await ws.send(b"hello")
            reply = await ws.recv()
            assert reply == b"hello"


async def test_async_iteration_closes_normally():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None) as ws:
            await ws.send("hello")
            assert await ws.recv() == "hello"
            await ws.close()

            items = []
            async for item in ws:
                items.append(item)

            assert items == []


async def test_ping_returns_waiter():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            pong_waiter = await ws.ping(b"abcd")
            latency = await asyncio.wait_for(pong_waiter, 1.0)
            assert latency >= 0


async def test_recv_streaming_fragmented_message():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None) as ws:
            await ws.send([b"ab", b"cd"])
            fragments = []
            async for fragment in ws.recv_streaming():
                fragments.append(fragment)
            assert fragments == [b"ab", b"cd"]


async def test_subprotocol_header_and_property():
    request_headers = {}

    def listener_factory(request):
        request_headers["value"] = request.headers.get("Sec-WebSocket-Protocol")
        return None

    async with WSServer(listener_factory) as server:
        with pytest.raises(websockets.InvalidStatus):
            async with websockets.connect(server.url, compression=None, subprotocols=["chat"]):
                pass

        assert request_headers["value"] == "chat"
