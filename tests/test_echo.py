import asyncio
import os

import pytest_asyncio

import picows
import pytest

URL = "ws://127.0.0.1:9001"


class WSFrameMaterialized:
    def __init__(self, frame: picows.WSFrame):
        self.opcode = frame.opcode
        self.payload_as_bytes = frame.get_payload_as_bytes()
        self.payload_as_bytes_from_mv = bytes(frame.get_payload_as_memoryview())
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
            self._transport.send(frame.opcode, frame.get_payload_as_bytes())
            if frame.opcode == picows.WSMsgType.CLOSE:
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
        def on_ws_connected(self, transport: picows.WSTransport):
            self.transport = transport
            self.msg_queue = asyncio.Queue()

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            self.msg_queue.put_nowait(WSFrameMaterialized(frame))

    (_, client) = await picows.ws_connect(URL, PicowsClientListener, "client")
    yield client

    # Teardown client
    client.transport.disconnect()
    await client.transport.wait_until_closed()


@pytest.mark.parametrize("msg_size", [32, 1024, 20000])
async def test_echo(echo_client, msg_size):
    msg = os.urandom(msg_size)
    echo_client.transport.send(picows.WSMsgType.BINARY, msg)
    frame: WSFrameMaterialized = await echo_client.msg_queue.get()
    assert frame.opcode == picows.WSMsgType.BINARY
    assert frame.payload_as_bytes == msg
    # assert frame.payload_as_ascii_text == msg.decode("ascii")
    assert frame.payload_as_bytes_from_mv == msg
