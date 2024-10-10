import asyncio
from idlelib.pyparse import trans

import async_timeout
import pytest
from aiohttp import WSMsgType

import picows
from picows import WSFrame
from tests.utils import ServerAsyncContext, TIMEOUT, TextFrame, CloseFrame, \
    BinaryFrame, materialize_frame


class AccumulatingListener(picows.WSListener):
    def __init__(self):
        self.frames = []

    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        self.frames.append(materialize_frame(frame))


class AccumulatingServerListener(picows.WSListener):
    def __init__(self, server_frames):
        self.frames = server_frames

    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        self.frames.append(materialize_frame(frame))



async def test_ping_pong():
    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0,
                                           enable_auto_ping=True,
                                           auto_ping_idle_timeout=0.1,
                                           auto_ping_reply_timeout=0.1)

    class ClientListener(picows.WSListener):
        def __init__(self):
            self.ping_count = 0

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.PING:
                self.ping_count += 1
                transport.send_pong()

            if self.ping_count == 3:
                transport.disconnect()

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, listener) = await picows.ws_connect(ClientListener, url)
        async with async_timeout.timeout(TIMEOUT):
            await transport.wait_disconnected()
            assert listener.ping_count == 3


async def test_custom_ping_consume_pong():
    server_frames = []

    class ServerClientListener(AccumulatingServerListener):
        def send_user_specific_ping(self, transport: picows.WSTransport):
            transport.send(WSMsgType.TEXT, b"ping")

        def is_user_specific_pong(self, frame: picows.WSFrame):
            return frame.get_payload_as_memoryview() == b"pong"

    server = await picows.ws_create_server(lambda _: ServerClientListener(server_frames),
                                           "127.0.0.1", 0,
                                           enable_auto_ping=True,
                                           auto_ping_idle_timeout=0.1,
                                           auto_ping_reply_timeout=0.1)

    class ClientListener(picows.WSListener):
        def __init__(self):
            self.ping_count = 0

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.TEXT and frame.get_payload_as_memoryview() == b"ping":
                self.ping_count += 1
                transport.send(picows.WSMsgType.TEXT, b"pong")

            if self.ping_count == 3:
                transport.disconnect()

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, listener) = await picows.ws_connect(ClientListener, url)
        async with async_timeout.timeout(TIMEOUT):
            transport.send(WSMsgType.TEXT, b"hello")
            await transport.wait_disconnected()

        assert listener.ping_count == 3
        assert len(server_frames) == 1
        assert server_frames[0].payload_as_ascii_text == "hello"


async def test_custom_ping_notify_pong():
    server_frames = []

    class ServerClientListener(AccumulatingServerListener):
        def send_user_specific_ping(self, transport: picows.WSTransport):
            transport.send(WSMsgType.TEXT, b"ping")

        def is_user_specific_pong(self, frame: picows.WSFrame):
            return False

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.get_payload_as_memoryview() == b"pong":
                transport.notify_user_specific_pong_received()
                return

            super().on_ws_frame(transport, frame)

    server = await picows.ws_create_server(lambda _: ServerClientListener(server_frames),
                                           "127.0.0.1", 0,
                                           enable_auto_ping=True,
                                           auto_ping_idle_timeout=0.1,
                                           auto_ping_reply_timeout=0.1)

    class ClientListener(picows.WSListener):
        def __init__(self):
            self.ping_count = 0

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.TEXT and frame.get_payload_as_memoryview() == b"ping":
                self.ping_count += 1
                transport.send(picows.WSMsgType.TEXT, b"pong")

            if self.ping_count == 3:
                transport.disconnect()

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, listener) = await picows.ws_connect(ClientListener, url)
        async with async_timeout.timeout(TIMEOUT):
            transport.send(WSMsgType.TEXT, b"hello")
            await transport.wait_disconnected()

        assert listener.ping_count == 3
        assert len(server_frames) == 1
        assert server_frames[0].payload_as_ascii_text == "hello"


async def test_no_pong_reply():
    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0,
                                           enable_auto_ping=True,
                                           auto_ping_idle_timeout=0.1,
                                           auto_ping_reply_timeout=0.1)

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, listener) = await picows.ws_connect(AccumulatingListener, url)
        async with async_timeout.timeout(TIMEOUT):
            await transport.wait_disconnected()

        assert len(listener.frames) == 2
        assert listener.frames[0].msg_type == picows.WSMsgType.PING
        assert listener.frames[1].msg_type == picows.WSMsgType.CLOSE
        assert listener.frames[1].close_code == picows.WSCloseCode.GOING_AWAY


async def test_no_ping_when_data_is_present():
    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0,
                                           enable_auto_ping=True,
                                           auto_ping_idle_timeout=0.1,
                                           auto_ping_reply_timeout=0.1)

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, listener) = await picows.ws_connect(AccumulatingListener, url)
        async with async_timeout.timeout(TIMEOUT):
            for i in range(5):
                await asyncio.sleep(0.05)
                transport.send(picows.WSMsgType.TEXT, b"hi")

            transport.disconnect()
            await transport.wait_disconnected()

        assert len(listener.frames) == 0


async def test_consume_pong_when_data_is_present():
    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0,
                                           enable_auto_ping=True,
                                           auto_ping_idle_timeout=0.1,
                                           auto_ping_reply_timeout=0.1)

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, listener) = await picows.ws_connect(AccumulatingListener, url)
        async with async_timeout.timeout(TIMEOUT):
            for i in range(5):
                await asyncio.sleep(0.05)
                transport.send(picows.WSMsgType.TEXT, b"hi")

            transport.disconnect()
            await transport.wait_disconnected()

        assert len(listener.frames) == 0


async def test_send_user_specific_ping_exception():
    class ServerClientListener(picows.WSListener):
        def send_user_specific_ping(self, transport: picows.WSTransport):
            raise RuntimeError("failed")

    server = await picows.ws_create_server(lambda _: ServerClientListener(),
                                           "127.0.0.1", 0,
                                           enable_auto_ping=True,
                                           auto_ping_idle_timeout=0.1,
                                           auto_ping_reply_timeout=0.1)

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, listener) = await picows.ws_connect(AccumulatingListener, url)
        async with async_timeout.timeout(TIMEOUT):
            await transport.wait_disconnected()

        assert len(listener.frames) == 1
        assert isinstance(listener.frames[0], CloseFrame)
        assert listener.frames[0].close_code == picows.WSCloseCode.INTERNAL_ERROR


async def test_is_user_specific_pong_exception():
    class ServerClientListener(picows.WSListener):
        def is_user_specific_pong(self, transport: picows.WSTransport):
            raise RuntimeError("failed")

    server = await picows.ws_create_server(lambda _: ServerClientListener(),
                                           "127.0.0.1", 0,
                                           enable_auto_ping=True,
                                           auto_ping_idle_timeout=0.1,
                                           auto_ping_reply_timeout=0.1)

    class ClientListener(AccumulatingListener):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.PING:
                transport.send_pong(frame.get_payload_as_bytes())

            super().on_ws_frame(transport, frame)

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, listener) = await picows.ws_connect(ClientListener, url)
        async with async_timeout.timeout(TIMEOUT):
            await transport.wait_disconnected()

        assert len(listener.frames) == 2
        assert listener.frames[0].msg_type == picows.WSMsgType.PING
        assert listener.frames[1].msg_type == picows.WSMsgType.CLOSE
        assert listener.frames[1].close_code == picows.WSCloseCode.INTERNAL_ERROR


@pytest.mark.parametrize("use_notify", [False, True], ids=["dont_use_notify", "use_notify"])
@pytest.mark.parametrize("with_auto_ping", [False, True], ids=["no_auto_ping", "with_auto_ping"])
async def test_roundtrip_time(use_notify, with_auto_ping):
    class ServerClientListener(picows.WSListener):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.PING:
                transport.send_pong(frame.get_payload_as_bytes())

    server = await picows.ws_create_server(lambda _: ServerClientListener(),
                                           "127.0.0.1", 0)

    class ClientListenerUseNotify(picows.WSListener):
        def is_user_specific_pong(self, frame):
            return False

        def on_ws_frame(self, transport, frame):
            if frame.msg_type == picows.WSMsgType.PONG:
                transport.notify_user_specific_pong_received()

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        listener_factory = ClientListenerUseNotify if use_notify else picows.WSListener
        (transport, listener) = await picows.ws_connect(listener_factory, url,
                                                        enable_auto_ping=with_auto_ping,
                                                        auto_ping_idle_timeout=0.5,
                                                        auto_ping_reply_timeout=0.5)
        async with async_timeout.timeout(2):
            results = await transport.measure_roundtrip_time(5)
            assert len(results) == 5
            for l in results:
                assert l > 0 and l < 1.0

        await asyncio.sleep(0.7)

        async with async_timeout.timeout(2):
            results = await transport.measure_roundtrip_time(5)
            assert len(results) == 5
            for l in results:
                assert l > 0 and l < 1.0
            transport.disconnect()

            await transport.wait_disconnected()


@pytest.mark.parametrize("with_auto_ping", [False, True], ids=["no_auto_ping", "with_auto_ping"])
async def test_roundtrip_latency_disconnect(with_auto_ping):
    class ServerClientListener(picows.WSListener):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.PING:
                transport.send_pong(frame.get_payload_as_bytes())

    server = await picows.ws_create_server(lambda _: ServerClientListener(),
                                           "127.0.0.1", 0)

    class ClientListener(picows.WSListener):
        def send_user_specific_ping(self, transport):
            transport.send_ping()
            # Disconnect immediately to test that the client will not hang up
            # waiting indefinitely for PONG
            transport.disconnect()

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, listener) = await picows.ws_connect(ClientListener, url,
                                                        enable_auto_ping=with_auto_ping,
                                                        auto_ping_idle_timeout=0.5,
                                                        auto_ping_reply_timeout=0.5)
        async with async_timeout.timeout(TIMEOUT):
            with pytest.raises(ConnectionResetError):
                await transport.measure_roundtrip_time(5)
