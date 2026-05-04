import asyncio

import pytest

import picows
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
            assert fragments == [b"ab", b"cd", b""]


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


async def test_send_waits_for_resume_writing():
    class TrackingConnection(websockets.ClientConnection):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.pause_event = asyncio.Event()

        def pause_writing(self) -> None:
            super().pause_writing()
            self.pause_event.set()

    async with WSServer() as server:
        async with websockets.connect(
            server.url,
            compression=None,
            create_connection=TrackingConnection,
        ) as ws:
            third_requested = asyncio.Event()
            allow_resume = asyncio.Event()

            async def fragments():
                ws.pause_writing()
                yield b"first"
                yield b"second"
                third_requested.set()
                yield b"third"

            async def resume_later():
                await allow_resume.wait()
                ws.resume_writing()

            asyncio.create_task(resume_later())

            send_task = asyncio.create_task(ws.send(fragments()))
            await asyncio.wait_for(ws.pause_event.wait(), 1.0)
            await asyncio.sleep(0)
            assert not third_requested.is_set()

            allow_resume.set()
            await asyncio.wait_for(send_task, 1.0)
            assert third_requested.is_set()

            reply = await ws.recv()
            assert reply == b"firstsecondthird"
