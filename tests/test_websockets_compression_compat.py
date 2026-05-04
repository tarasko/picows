from contextlib import asynccontextmanager

import websockets as upstream_websockets

from picows import websockets


@asynccontextmanager
async def upstream_server(handler):
    server = await upstream_websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression="deflate",
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"ws://127.0.0.1:{port}/"
    finally:
        server.close()
        await server.wait_closed()


async def test_permessage_deflate_echo_with_upstream_server():
    async def handler(ws):
        async for message in ws:
            await ws.send(message)

    async with upstream_server(handler) as url:
        async with websockets.connect(url, ping_interval=None) as ws:
            assert "permessage-deflate" in (ws.response.headers.get("Sec-WebSocket-Extensions") or "")

            message = "hello " * 1000
            await ws.send(message)
            assert await ws.recv() == message


async def test_permessage_deflate_fragmented_send_with_upstream_server():
    async def handler(ws):
        async for message in ws:
            await ws.send(message)

    async with upstream_server(handler) as url:
        async with websockets.connect(url, ping_interval=None) as ws:
            await ws.send([b"a" * 300, b"b" * 300, b"c" * 300])
            assert await ws.recv() == (b"a" * 300 + b"b" * 300 + b"c" * 300)


async def test_permessage_deflate_recv_streaming_from_upstream_server():
    chunks = [b"ab" * 300, b"cd" * 300, b"ef" * 300]

    async def handler(ws):
        await ws.send(chunks)
        await ws.close()

    async with upstream_server(handler) as url:
        async with websockets.connect(url, ping_interval=None) as ws:
            fragments = []
            async for fragment in ws.recv_streaming():
                fragments.append(fragment)
            assert fragments == chunks + [b""]
