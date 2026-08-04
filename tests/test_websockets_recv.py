import asyncio

import picows
import pytest

from picows import websockets
from tests.utils import ServerEchoListener, WSServer


class SendTextOnConnect(ServerEchoListener):
    def __init__(self, payload: bytes):
        self._payload = payload

    def on_ws_connected(self, transport: picows.WSTransport):
        super().on_ws_connected(transport)
        transport.send(picows.WSMsgType.TEXT, self._payload)


class SendBinaryOnConnect(ServerEchoListener):
    def __init__(self, payload: bytes):
        self._payload = payload

    def on_ws_connected(self, transport: picows.WSTransport):
        super().on_ws_connected(transport)
        transport.send(picows.WSMsgType.BINARY, self._payload)


class FragmentedTextListener(ServerEchoListener):
    def __init__(self, allow_first_fragment: asyncio.Event, allow_second_fragment: asyncio.Event):
        self._allow_first_fragment = allow_first_fragment
        self._allow_second_fragment = allow_second_fragment

    def on_ws_connected(self, transport: picows.WSTransport):
        super().on_ws_connected(transport)

        async def send_fragments():
            await self._allow_first_fragment.wait()
            transport.send(picows.WSMsgType.TEXT, b"he", fin=False)
            await self._allow_second_fragment.wait()
            transport.send(picows.WSMsgType.CONTINUATION, b"llo", fin=True)

        asyncio.create_task(send_fragments())


class ContinuationOnConnect(ServerEchoListener):
    def on_ws_connected(self, transport: picows.WSTransport):
        super().on_ws_connected(transport)
        transport.send(picows.WSMsgType.CONTINUATION, b"bad", fin=True)


class Rsv1OnConnect(ServerEchoListener):
    def on_ws_connected(self, transport: picows.WSTransport):
        super().on_ws_connected(transport)
        transport.send(picows.WSMsgType.TEXT, b"bad", fin=True, rsv1=True)


class BadContinuationSequenceOnConnect(ServerEchoListener):
    def on_ws_connected(self, transport: picows.WSTransport):
        super().on_ws_connected(transport)
        transport.send(picows.WSMsgType.TEXT, b"first", fin=False)
        transport.send(picows.WSMsgType.TEXT, b"second", fin=True)


class SendLargeTextOnConnect(ServerEchoListener):
    def on_ws_connected(self, transport: picows.WSTransport):
        super().on_ws_connected(transport)
        transport.send(picows.WSMsgType.TEXT, b"large")


class DelayedFragmentedTextOnConnect(ServerEchoListener):
    def on_ws_connected(self, transport: picows.WSTransport):
        super().on_ws_connected(transport)

        async def send_fragments():
            transport.send(picows.WSMsgType.TEXT, b"he", fin=False)
            await asyncio.sleep(0.01)
            transport.send(picows.WSMsgType.CONTINUATION, b"llo", fin=True)

        asyncio.create_task(send_fragments())


class FragmentedTextOnConnect(ServerEchoListener):
    def on_ws_connected(self, transport: picows.WSTransport):
        super().on_ws_connected(transport)
        transport.send(picows.WSMsgType.TEXT, b"he", fin=False)
        transport.send(picows.WSMsgType.CONTINUATION, b"llo", fin=True)


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


async def test_recv_streaming_fragmented_message():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None) as ws:
            await ws.send([b"ab", b"cd"])
            fragments = []
            async for fragment in ws.recv_streaming():
                fragments.append(fragment)
            assert fragments == [b"ab", b"cd", b""]


async def test_recv_cancellation_is_safe_for_fragmented_message():
    allow_first_fragment = asyncio.Event()
    allow_second_fragment = asyncio.Event()

    async with WSServer(lambda _: FragmentedTextListener(allow_first_fragment, allow_second_fragment)) as server:
        async with websockets.connect(server.url, compression=None) as ws:
            recv_task = asyncio.create_task(ws.recv())
            allow_first_fragment.set()
            await asyncio.sleep(0)
            recv_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await recv_task

            allow_second_fragment.set()
            assert await ws.recv() == "hello"


async def test_recv_streaming_cancellation_before_first_fragment_is_safe():
    allow_first_fragment = asyncio.Event()
    allow_second_fragment = asyncio.Event()

    async with WSServer(lambda _: FragmentedTextListener(allow_first_fragment, allow_second_fragment)) as server:
        async with websockets.connect(server.url, compression=None) as ws:
            iterator = ws.recv_streaming()
            recv_task = asyncio.create_task(iterator.__anext__())
            recv_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await recv_task

            allow_first_fragment.set()
            allow_second_fragment.set()
            assert await ws.recv() == "hello"


async def test_recv_streaming_partial_consumption_breaks_future_receives():
    allow_first_fragment = asyncio.Event()
    allow_second_fragment = asyncio.Event()

    async with WSServer(lambda _: FragmentedTextListener(allow_first_fragment, allow_second_fragment)) as server:
        async with websockets.connect(server.url, compression=None) as ws:
            iterator = ws.recv_streaming()
            allow_first_fragment.set()
            assert await iterator.__anext__() == "he"

            with pytest.raises(websockets.ConcurrencyError):
                await ws.recv()

            allow_second_fragment.set()

            with pytest.raises(websockets.ConcurrencyError):
                await ws.recv()


async def test_recv_decode_false_returns_bytes_for_text_messages():
    async with WSServer(lambda _: SendTextOnConnect(b"hello")) as server:
        async with websockets.connect(server.url, compression=None) as ws:
            assert await ws.recv(decode=False) == b"hello"


async def test_recv_decode_true_returns_text_for_binary_messages():
    async with WSServer(lambda _: SendBinaryOnConnect(b"hello")) as server:
        async with websockets.connect(server.url, compression=None) as ws:
            assert await ws.recv(decode=True) == "hello"


async def test_recv_streaming_decode_false_returns_bytes_for_text_messages():
    async with WSServer(lambda _: SendTextOnConnect(b"hello")) as server:
        async with websockets.connect(server.url, compression=None) as ws:
            fragments = []
            async for fragment in ws.recv_streaming(decode=False):
                fragments.append(fragment)
            assert fragments == [b"hello"]


async def test_recv_streaming_decode_true_returns_text_for_binary_messages():
    async with WSServer(lambda _: SendBinaryOnConnect(b"hello")) as server:
        async with websockets.connect(server.url, compression=None) as ws:
            fragments = []
            async for fragment in ws.recv_streaming(decode=True):
                fragments.append(fragment)
            assert fragments == ["hello"]


async def test_recv_decode_true_invalid_utf8_closes_connection():
    async with WSServer(lambda _: SendBinaryOnConnect(b"\xff\xfe")) as server:
        async with websockets.connect(server.url, compression=None) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv(decode=True)
            assert ws.close_code == 1007


async def test_recv_streaming_decode_true_invalid_utf8_closes_connection():
    async with WSServer(lambda _: SendBinaryOnConnect(b"\xff\xfe")) as server:
        async with websockets.connect(server.url, compression=None) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                async for _fragment in ws.recv_streaming(decode=True):
                    pass
            assert ws.close_code == 1007


async def test_recv_rejects_unexpected_continuation_and_rsv1():
    async with WSServer(lambda _: ContinuationOnConnect()) as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()

    async with WSServer(lambda _: Rsv1OnConnect()) as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()


async def test_recv_rejects_bad_continuation_and_too_large_message():
    async with WSServer(lambda _: BadContinuationSequenceOnConnect()) as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()

    async with WSServer(lambda _: SendLargeTextOnConnect()) as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None, max_size=2) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()


async def test_recv_streaming_waits_for_later_fragment():
    async with WSServer(lambda _: DelayedFragmentedTextOnConnect()) as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            fragments = []
            async for fragment in ws.recv_streaming():
                fragments.append(fragment)
            assert fragments == ["he", "llo"]


async def test_fragmented_message_exceeding_max_size_closes_connection():
    async with WSServer(lambda _: FragmentedTextOnConnect()) as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None, max_size=4) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()


async def test_tuple_max_size_applies_message_limit_to_client_wrapper():
    async with WSServer(lambda _: FragmentedTextOnConnect()) as server:
        async with websockets.connect(
            server.url,
            compression=None,
            ping_interval=None,
            max_size=(4, 10),
        ) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()


async def test_tuple_max_size_applies_frame_limit_to_client_core():
    async with WSServer(lambda _: SendLargeTextOnConnect()) as server:
        async with websockets.connect(
            server.url,
            compression=None,
            ping_interval=None,
            max_size=(10, 2),
        ) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()


async def test_disconnect_without_close_frame_sets_error_close_state():
    async with WSServer() as server:
        async with websockets.connect(server.url, compression=None, ping_interval=None) as ws:
            await ws.send("disconnect_me_without_close_frame")
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()
            assert ws.close_code is None
            assert ws.close_reason is None
