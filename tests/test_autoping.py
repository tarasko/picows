import asyncio

import async_timeout
import pytest

import picows
from tests.utils import (ServerAsyncContext, ClientAsyncContext, TIMEOUT,
                         CloseFrame, materialize_frame, WSServer, WSClient,
                         AsyncClient)


class AccumulatingListener(picows.WSListener):
    def __init__(self):
        self.frames = []

    def on_ws_connected(self, transport):
        self.transport = transport

    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        self.frames.append(materialize_frame(frame))


class AccumulatingServerListener(picows.WSListener):
    def __init__(self, server_frames):
        self.frames = server_frames

    def on_ws_connected(self, transport):
        self.transport = transport

    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        self.frames.append(materialize_frame(frame))


async def test_ping_pong():
    class ClientListener(AsyncClient):
        def __init__(self):
            super().__init__()
            self.ping_count = 0

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.PING:
                self.ping_count += 1
                transport.send_pong()

            if self.ping_count == 3:
                transport.disconnect()

    async with async_timeout.timeout(TIMEOUT):
        async with WSServer(lambda _: picows.WSListener(),
                            enable_auto_ping=True,
                            auto_ping_idle_timeout=0.1,
                            auto_ping_reply_timeout=0.1,
                            enable_auto_pong=False
                            ) as server:
            async with WSClient(server, ClientListener, enable_auto_pong=False) as client:
                await client.transport.wait_disconnected()
                assert client.ping_count == 3


async def test_custom_ping_consume_pong():
    # Test that for if is_user_specific_pong() is True then this message is
    # considered a pong and is not delivered to on_ws_frame

    server_frames = []

    class ServerClientListener(AccumulatingServerListener):
        def send_user_specific_ping(self, transport: picows.WSTransport):
            transport.send(picows.WSMsgType.TEXT, b"ping")

        def is_user_specific_pong(self, frame: picows.WSFrame):
            return frame.get_payload_as_memoryview() == b"pong"

    class ClientListener(AsyncClient):
        def __init__(self):
            super().__init__()
            self.ping_count = 0

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.TEXT and frame.get_payload_as_memoryview() == b"ping":
                self.ping_count += 1
                transport.send(picows.WSMsgType.TEXT, b"pong")

            if self.ping_count == 3:
                transport.disconnect()

    async with WSServer(lambda _: ServerClientListener(server_frames),
                        enable_auto_ping=True,
                        auto_ping_idle_timeout=0.1,
                        auto_ping_reply_timeout=0.1,
                        enable_auto_pong=False) as server:
        async with async_timeout.timeout(TIMEOUT):
            async with WSClient(server, ClientListener, enable_auto_pong=False) as client:
                # Will check that b"hello" was delivered to on_ws_frame and custom ping message not.
                client.transport.send(picows.WSMsgType.TEXT, b"hello")
                await client.transport.wait_disconnected()

                assert client.ping_count == 3
                assert len(server_frames) == 1
                assert server_frames[0].payload_as_ascii_text == "hello"


async def test_custom_ping_notify_pong():
    server_frames = []

    class ServerClientListener(AccumulatingServerListener):
        def send_user_specific_ping(self, transport: picows.WSTransport):
            transport.send(picows.WSMsgType.TEXT, b"ping")

        def is_user_specific_pong(self, frame: picows.WSFrame):
            return False

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.get_payload_as_memoryview() == b"pong":
                transport.notify_user_specific_pong_received()
                return

            super().on_ws_frame(transport, frame)

    class ClientListener(picows.WSListener):
        def __init__(self):
            self.ping_count = 0

        def on_ws_connected(self, transport):
            self.transport = transport

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.TEXT and frame.get_payload_as_memoryview() == b"ping":
                self.ping_count += 1
                transport.send(picows.WSMsgType.TEXT, b"pong")

            if self.ping_count == 3:
                transport.disconnect()

    async with WSServer(lambda _: ServerClientListener(server_frames),
                        enable_auto_ping=True,
                        auto_ping_idle_timeout=0.1,
                        auto_ping_reply_timeout=0.1,
                        enable_auto_pong=False) as server:
        async with async_timeout.timeout(TIMEOUT):
            async with WSClient(server, ClientListener, enable_auto_pong=False) as client:
                client.transport.send(picows.WSMsgType.TEXT, b"hello")
                await client.transport.wait_disconnected()

                assert client.ping_count == 3
                assert len(server_frames) == 1
                assert server_frames[0].payload_as_ascii_text == "hello"


async def test_no_pong_reply():
    async with WSServer(lambda _: picows.WSListener(),
                        enable_auto_ping=True,
                        auto_ping_idle_timeout=0.1,
                        auto_ping_reply_timeout=0.1,
                        enable_auto_pong=False) as server:
        async with async_timeout.timeout(TIMEOUT):
            async with WSClient(server, AccumulatingListener,
                                enable_auto_pong=False) as client:
                await client.transport.wait_disconnected()

                assert len(client.frames) == 2
                assert client.frames[0].msg_type == picows.WSMsgType.PING
                assert client.frames[1].msg_type == picows.WSMsgType.CLOSE
                assert client.frames[1].close_code == picows.WSCloseCode.GOING_AWAY


async def test_no_ping_when_data_is_present():
    # for PING_WHEN_IDLE, it is by default, we should not receive PING when data present
    async with WSServer(lambda _: picows.WSListener(),
                        enable_auto_ping=True,
                        auto_ping_idle_timeout=0.1,
                        auto_ping_reply_timeout=0.1,
                        enable_auto_pong=False) as server:
        async with WSClient(server, AccumulatingListener, enable_auto_pong=False) as client:
            for i in range(50):
                await asyncio.sleep(0.02)
                client.transport.send(picows.WSMsgType.TEXT, b"hi")

        assert len(client.frames) == 0


async def test_periodic_ping_when_data_is_present():
    # for PING_PERIODICALLY, server keeps pinging client even if client constantly sends data

    class ClientListener(AccumulatingListener):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.PING:
                transport.send_pong(frame.get_payload_as_bytes())

            super().on_ws_frame(transport, frame)

    async with WSServer(lambda _: picows.WSListener(),
                        enable_auto_ping=True,
                        auto_ping_idle_timeout=0.1,
                        auto_ping_reply_timeout=0.1,
                        auto_ping_strategy=picows.WSAutoPingStrategy.PING_PERIODICALLY,
                        enable_auto_pong=False
                        ) as server:
        async with WSClient(server, ClientListener,
                            enable_auto_pong=False) as client:
            for i in range(50):
                await asyncio.sleep(0.02)
                client.transport.send(picows.WSMsgType.TEXT, b"hi")

            assert len(client.frames) >= 3
            for f in client.frames:
                assert f.msg_type == picows.WSMsgType.PING


async def test_send_user_specific_ping_exception():
    # Expect server to disconnect us with CLOSE(INTERNAL_ERROR) when send_user_specific_ping throws
    class ServerClientListener(picows.WSListener):
        def send_user_specific_ping(self, transport: picows.WSTransport):
            raise RuntimeError("failed")

    async with WSServer(lambda _: ServerClientListener(),
                        enable_auto_ping=True,
                        auto_ping_idle_timeout=0.1,
                        auto_ping_reply_timeout=0.1,
                        enable_auto_pong=False) as server:

        async with async_timeout.timeout(TIMEOUT):
            async with WSClient(server, AccumulatingListener,
                                enable_auto_pong=False) as client:
                await client.transport.wait_disconnected()

                assert len(client.frames) == 1
                assert isinstance(client.frames[0], CloseFrame)
                assert client.frames[0].close_code == picows.WSCloseCode.INTERNAL_ERROR


async def test_is_user_specific_pong_exception():
    # Expect server to disconnect us with CLOSE(INTERNAL_ERROR) when is_user_specific_pong throws
    # Use auto_pong on client to reply to pings

    class ServerClientListener(picows.WSListener):
        def is_user_specific_pong(self, frame: picows.WSFrame):
            raise RuntimeError("failed")

    async with WSServer(lambda _: ServerClientListener(),
                        enable_auto_ping=True,
                        auto_ping_idle_timeout=0.1,
                        auto_ping_reply_timeout=0.1
                        ) as server:

        async with async_timeout.timeout(TIMEOUT):
            async with WSClient(server, AccumulatingListener,
                                enable_auto_pong=True) as client:
                await client.transport.wait_disconnected()

                assert len(client.frames) == 1
                assert client.frames[0].msg_type == picows.WSMsgType.CLOSE
                assert client.frames[0].close_code == picows.WSCloseCode.INTERNAL_ERROR


@pytest.mark.parametrize("use_notify", [False, True], ids=["dont_use_notify", "use_notify"])
@pytest.mark.parametrize("auto_ping_strategy",
                         [None, picows.WSAutoPingStrategy.PING_WHEN_IDLE, picows.WSAutoPingStrategy.PING_PERIODICALLY],
                         ids=["no_auto_ping", "auto_ping_when_idle", "auto_ping_periodically"])
async def test_roundtrip_time(use_notify, auto_ping_strategy):
    class ClientListenerUseNotify(picows.WSListener):
        def is_user_specific_pong(self, frame):
            return False

        def on_ws_frame(self, transport, frame):
            if frame.msg_type == picows.WSMsgType.PONG:
                transport.notify_user_specific_pong_received()

    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0)

    async with ServerAsyncContext(server) as server_ctx:
        client_listener_factory = ClientListenerUseNotify if use_notify else picows.WSListener
        client_enable_auto_ping = auto_ping_strategy is not None
        client_auto_ping_strategy = auto_ping_strategy or picows.WSAutoPingStrategy.PING_WHEN_IDLE
        async with ClientAsyncContext(client_listener_factory, server_ctx.tcp_url,
                                      enable_auto_ping=client_enable_auto_ping,
                                      auto_ping_idle_timeout=0.5,
                                      auto_ping_reply_timeout=0.5,
                                      auto_ping_strategy=client_auto_ping_strategy,
                                      enable_auto_pong=True) as (transport, listener):

            async with async_timeout.timeout(2):
                results = await transport.measure_roundtrip_time(5)
                assert len(results) == 5
                for rtt in results:
                    assert rtt > 0 and rtt < 1.0

            await asyncio.sleep(0.7)

            async with async_timeout.timeout(2):
                results = await transport.measure_roundtrip_time(5)
                assert len(results) == 5
                for rtt in results:
                    assert rtt > 0 and rtt < 1.0


@pytest.mark.parametrize("with_auto_ping", [False, True], ids=["no_auto_ping", "with_auto_ping"])
async def test_roundtrip_latency_disconnect(with_auto_ping):
    class ClientListener(picows.WSListener):
        def send_user_specific_ping(self, transport):
            transport.send_ping()
            # Disconnect immediately to test that the client will not hang up
            # waiting indefinitely for PONG
            transport.disconnect()

    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0)

    async with async_timeout.timeout(TIMEOUT):
        async with ServerAsyncContext(server) as server_ctx:
            async with ClientAsyncContext(ClientListener, server_ctx.tcp_url,
                                          enable_auto_ping=with_auto_ping,
                                          auto_ping_idle_timeout=0.5,
                                          auto_ping_reply_timeout=0.5) as (transport, listener):
                with pytest.raises(ConnectionResetError):
                    await transport.measure_roundtrip_time(5)
