import asyncio
import base64
import os

import pytest_asyncio

import picows
import pytest
import async_timeout

URL = "ws://127.0.0.1:9001"


class BinaryFrame:
    def __init__(self, frame: picows.WSFrame):
        self.msg_type = frame.msg_type
        self.payload_as_bytes = frame.get_payload_as_bytes()
        self.payload_as_bytes_from_mv = bytes(frame.get_payload_as_memoryview())
        self.fin = frame.fin


class TextFrame:
    def __init__(self, frame: picows.WSFrame):
        self.msg_type = frame.msg_type
        self.payload_as_ascii_text = frame.get_payload_as_ascii_text()
        self.payload_as_utf8_text = frame.get_payload_as_utf8_text()
        self.fin = frame.fin


class CloseFrame:
    def __init__(self, frame: picows.WSFrame):
        self.msg_type = frame.msg_type
        self.close_code = frame.get_close_code()
        self.close_message = frame.get_close_message()
        self.fin = frame.fin


#@pytest.fixture(scope="module")
@pytest.fixture
async def echo_server():
    class PicowsServerListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            print("echo_server:on_ws_connected")
            self._transport = transport

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            print("echo_server:on_ws_frame")
            self._transport.send(frame.msg_type, frame.get_payload_as_bytes())
            if frame.msg_type == picows.WSMsgType.CLOSE:
                self._transport.send_close(frame.get_close_code(), frame.get_close_message())
                self._transport.disconnect()

    server = await picows.ws_create_server(URL, PicowsServerListener, "server")
    task = asyncio.create_task(server.serve_forever())
    print("initiated module level echo server")
    yield server

    # Teardown server
    task.cancel()
    try:
        await(task)
    except:
        pass

    print("stopped module level echo server")


# @pytest.fixture(scope="module")
@pytest.fixture
async def echo_client(echo_server):
    class PicowsClientListener(picows.WSListener):
        transport: picows.WSTransport
        msg_queue: asyncio.Queue

        def on_ws_connected(self, transport: picows.WSTransport):
            self.transport = transport
            self.msg_queue = asyncio.Queue()

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.TEXT:
                self.msg_queue.put_nowait(TextFrame(frame))
            elif frame.msg_type == picows.WSMsgType.CLOSE:
                self.msg_queue.put_nowait(CloseFrame(frame))
            else:
                self.msg_queue.put_nowait(BinaryFrame(frame))

        async def get_message(self):
            async with async_timeout.timeout(1):
                return await self.msg_queue.get()

    (_, client) = await picows.ws_connect(URL, PicowsClientListener, "client")
    yield client

    # Teardown client
    client.transport.send_close(picows.WSCloseCode.GOING_AWAY, b"poka poka")
    try:
        # Gracefull shutdown, expect server to disconnect us because we have sent close message
        async with async_timeout.timeout(1):
            await client.transport.wait_until_closed()
    finally:
        client.transport.disconnect()


@pytest.mark.parametrize("msg_size", [32, 1024, 20000])
async def test_echo(echo_client, msg_size):
    msg = os.urandom(msg_size)
    echo_client.transport.send(picows.WSMsgType.BINARY, msg)
    frame = await echo_client.get_message()
    assert frame.msg_type == picows.WSMsgType.BINARY
    assert frame.payload_as_bytes == msg
    assert frame.payload_as_bytes_from_mv == msg

    msg = base64.b64encode(msg)
    echo_client.transport.send(picows.WSMsgType.TEXT, msg)
    frame = await echo_client.get_message()
    assert frame.msg_type == picows.WSMsgType.TEXT
    assert frame.payload_as_ascii_text == msg.decode("ascii")
    assert frame.payload_as_utf8_text == msg.decode("utf8")


async def test_close(echo_client):
    echo_client.transport.send_close(picows.WSCloseCode.GOING_AWAY, b"goodbay")
    frame = await echo_client.get_message()
    assert frame.msg_type == picows.WSMsgType.CLOSE
    assert frame.close_code == picows.WSCloseCode.GOING_AWAY
    assert frame.close_message == b"goodbay"
