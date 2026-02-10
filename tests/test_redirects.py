import asyncio
from http import HTTPStatus

import async_timeout
import pytest

import picows
from tests.utils import ServerAsyncContext, get_server_port


class ServerEchoListener(picows.WSListener):
    def on_ws_connected(self, transport: picows.WSTransport):
        self._transport = transport

    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        if frame.msg_type == picows.WSMsgType.CLOSE:
            self._transport.send_close(frame.get_close_code(), frame.get_close_message())
            self._transport.disconnect()
        if (frame.msg_type == picows.WSMsgType.TEXT and
                frame.get_payload_as_memoryview() == b"disconnect_me_without_close_frame"):
            self._transport.disconnect()
        else:
            self._transport.send(frame.msg_type, frame.get_payload_as_bytes(), frame.fin, frame.rsv1)


async def test_redirect_chain():
    def final_listener_factory(r):
        return ServerEchoListener()

    final_server = await picows.ws_create_server(final_listener_factory, "127.0.0.1", 0)

    def redirect_1_listener_factory(r):
        resp = picows.WSUpgradeResponse.create_redirect_response(
            HTTPStatus.MOVED_PERMANENTLY,
            f"ws://127.0.0.1:{get_server_port(final_server)}"
        )
        return picows.WSUpgradeResponseWithListener(resp, None)

    redirect_1_server = await picows.ws_create_server(redirect_1_listener_factory, "127.0.0.1", 0)

    def redirect_2_listener_factory(r):
        resp = picows.WSUpgradeResponse.create_redirect_response(
            HTTPStatus.MOVED_PERMANENTLY,
            f"ws://127.0.0.1:{get_server_port(redirect_1_server)}"
        )
        return picows.WSUpgradeResponseWithListener(resp, None)

    redirect_2_server = await picows.ws_create_server(redirect_2_listener_factory, "127.0.0.1", 0)

    url = f"ws://127.0.0.1:{get_server_port(redirect_2_server)}"

    class ClientListener(picows.WSListener):
        def __init__(self):
            self.msg_fut = asyncio.get_running_loop().create_future()

        def on_ws_connected(self, transport):
            transport.send(picows.WSMsgType.TEXT, b"hello")

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.TEXT and frame.get_payload_as_memoryview() == b"hello":
                self.msg_fut.set_result(True)
                transport.disconnect()

    async with ServerAsyncContext(final_server), ServerAsyncContext(redirect_1_server), ServerAsyncContext(redirect_2_server):
        (transport, listener) = await picows.ws_connect(ClientListener, url)
        async with async_timeout.timeout(1.0):
            await listener.msg_fut

        with pytest.raises(picows.WSError, match="status 101"):
            await picows.ws_connect(ClientListener, url, max_redirects=0)

        with pytest.raises(picows.WSError, match="status 101"):
            await picows.ws_connect(ClientListener, url, max_redirects=1)
