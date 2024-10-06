import async_timeout
from aiohttp import WSMsgType

import picows
from picows import WSFrame
from tests.utils import ServerAsyncContext, TIMEOUT


async def test_basic():
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


async def test_custom_ping():
    class ServerClientListener(picows.WSListener):
        def send_user_specific_ping(self, transport: picows.WSTransport):
            transport.send(WSMsgType.TEXT, b"ping")

        def is_user_specific_pong(self, frame: WSFrame):
            return frame.get_payload_as_memoryview() == b"pong"

    server = await picows.ws_create_server(lambda _: ServerClientListener(),
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
            await transport.wait_disconnected()
            assert listener.ping_count == 3


async def test_no_pong():
    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0,
                                           enable_auto_ping=True,
                                           auto_ping_idle_timeout=0.1,
                                           auto_ping_reply_timeout=0.1)

    class ClientListener(picows.WSListener):
        def __init__(self):
            self.close_received = False

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.CLOSE:
                assert frame.get_close_code() == picows.WSCloseCode.GOING_AWAY
                self.close_received = True

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, listener) = await picows.ws_connect(ClientListener, url)
        async with async_timeout.timeout(TIMEOUT):
            await transport.wait_disconnected()
            assert listener.close_received
