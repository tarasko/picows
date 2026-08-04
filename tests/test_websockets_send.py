import asyncio
from collections.abc import AsyncIterator

import pytest

from picows import websockets
from tests.utils import WSServer


class FragmentError(Exception):
    pass


async def test_connect_send_recv_text():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None) as ws:
            await ws.send("hello")
            assert await ws.recv() == "hello"


async def test_connect_send_recv_binary():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None) as ws:
            await ws.send(b"hello")
            assert await ws.recv() == b"hello"


async def test_send_empty_iterable_is_noop():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            await ws.send([])
            pong_waiter = await ws.ping(b"noop")
            await asyncio.wait_for(pong_waiter, 1.0)


async def test_send_empty_async_iterable_is_noop():
    async def fragments() -> AsyncIterator[bytes]:
        if False:
            yield b"never"

    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            await ws.send(fragments())
            pong_waiter = await ws.ping(b"noop")
            await asyncio.wait_for(pong_waiter, 1.0)


async def test_send_rejects_dict_like_objects():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None) as ws:
            with pytest.raises(TypeError, match="dict-like object"):
                await ws.send({"a": 1})


async def test_send_text_overrides_and_concurrent_send_waits_for_turn():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            await ws.send("as-binary", text=False)
            assert await ws.recv(decode=False) == b"as-binary"

            await ws.send(b"as-text", text=True)
            assert await ws.recv() == "as-text"

            first_sent = asyncio.Event()
            release = asyncio.Event()

            async def fragments():
                yield b"first"
                first_sent.set()
                await release.wait()
                yield b"second"

            first_send = asyncio.create_task(ws.send(fragments()))
            await asyncio.wait_for(first_sent.wait(), 1.0)

            second_send = asyncio.create_task(ws.send(b"after"))
            await asyncio.sleep(0)
            assert not second_send.done()

            release.set()
            await asyncio.wait_for(first_send, 1.0)
            await asyncio.wait_for(second_send, 1.0)
            assert await ws.recv() == b"firstsecond"
            assert await ws.recv() == b"after"


async def test_send_string_fragments_and_write_pause_wait_paths():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            await ws.send(["he", "llo"])
            assert await ws.recv() == "hello"

            ws.pause_writing()
            single_send = asyncio.create_task(ws.send(b"paused"))
            await asyncio.sleep(0)
            assert not single_send.done()
            ws.resume_writing()
            await asyncio.wait_for(single_send, 1.0)
            assert await ws.recv() == b"paused"

            ws.pause_writing()
            fragmented_send = asyncio.create_task(ws.send([b"frag", b"mented"]))
            await asyncio.sleep(0)
            assert not fragmented_send.done()
            ws.resume_writing()
            await asyncio.wait_for(fragmented_send, 1.0)
            assert await ws.recv() == b"fragmented"


async def test_send_rejects_invalid_first_fragment_and_closes():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            with pytest.raises(TypeError, match="message must contain"):
                await ws.send([object()])  # type: ignore[list-item]
            await asyncio.wait_for(ws.wait_closed(), 1.0)
            assert ws.state is websockets.State.CLOSED


async def test_send_rejects_unsupported_object_and_mixed_fragments():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            with pytest.raises(TypeError, match="unsupported type"):
                await ws.send(object())  # type: ignore[arg-type]
            with pytest.raises(TypeError, match="same category"):
                await ws.send([b"bytes", "text"])


async def test_send_sync_iterable_exception_closes_connection():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            def fragments():
                yield b"first"
                raise FragmentError("boom")

            with pytest.raises(FragmentError, match="boom"):
                await ws.send(fragments())

            await asyncio.wait_for(ws.wait_closed(), 1.0)
            with pytest.raises(websockets.ConnectionClosed):
                await ws.send(b"x")


async def test_send_async_iterable_exception_closes_connection():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            async def fragments() -> AsyncIterator[bytes]:
                yield b"first"
                raise FragmentError("boom")

            with pytest.raises(FragmentError, match="boom"):
                await ws.send(fragments())

            await asyncio.wait_for(ws.wait_closed(), 1.0)
            with pytest.raises(websockets.ConnectionClosed):
                await ws.send(b"x")


async def test_send_async_iterable_cancellation_closes_connection():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            first_sent = asyncio.Event()
            unblock = asyncio.Event()

            async def fragments() -> AsyncIterator[bytes]:
                yield b"first"
                first_sent.set()
                await unblock.wait()
                yield b"second"

            send_task = asyncio.create_task(ws.send(fragments()))
            await asyncio.wait_for(first_sent.wait(), 1.0)
            send_task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await send_task

            await asyncio.wait_for(ws.wait_closed(), 1.0)
            with pytest.raises(websockets.ConnectionClosed):
                await ws.send(b"x")


async def test_close_during_fragmented_send_closes_connection():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            first_sent = asyncio.Event()
            unblock = asyncio.Event()

            async def fragments() -> AsyncIterator[bytes]:
                yield b"first"
                first_sent.set()
                await unblock.wait()
                yield b"second"

            send_task = asyncio.create_task(ws.send(fragments()))
            await asyncio.wait_for(first_sent.wait(), 1.0)
            await ws.close()
            unblock.set()

            with pytest.raises(websockets.ConnectionClosed):
                await send_task


async def test_send_after_close_raises_connection_closed():
    async with WSServer() as server:
        ws = await websockets.connect(server.url, compression=None, ping_interval=None)
        await ws.close()

        with pytest.raises(websockets.ConnectionClosedOK):
            await ws.send(b"closed")
