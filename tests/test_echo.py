import asyncio
import base64
import os
import pathlib
import ssl

import picows
import pytest
import async_timeout

URL = "ws://127.0.0.1:9001"
URL_SSL = "wss://127.0.0.1:9002"


def create_server_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(pathlib.Path(__file__).parent / "picows_test.crt",
                                pathlib.Path(__file__).parent / "picows_test.key")
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


def create_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


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


@pytest.fixture(params=[URL, URL_SSL])
async def echo_server(request):
    class PicowsServerListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            self._transport = transport

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            self._transport.send(frame.msg_type, frame.get_payload_as_bytes())
            if frame.msg_type == picows.WSMsgType.CLOSE:
                self._transport.send_close(frame.get_close_code(), frame.get_close_message())
                self._transport.disconnect()

    server = await picows.ws_create_server(request.param, PicowsServerListener, "server",
                                           ssl_context=create_server_ssl_context())
    task = asyncio.create_task(server.serve_forever())
    yield request.param

    # Teardown server
    task.cancel()
    try:
        await task
    except:
        pass


@pytest.fixture()
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

    (_, client) = await picows.ws_connect(echo_server, PicowsClientListener, "client",
                                          ssl=create_client_ssl_context())
    yield client

    # Teardown client
    client.transport.send_close(picows.WSCloseCode.GOING_AWAY, b"poka poka")
    try:
        # Gracefull shutdown, expect server to disconnect us because we have sent close message
        async with async_timeout.timeout(1):
            await client.transport.wait_until_closed()
    finally:
        client.transport.disconnect()


@pytest.mark.parametrize("msg_size", [256, 1024, 256 * 1024])
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
    echo_client.transport.send_close(picows.WSCloseCode.GOING_AWAY, b"goodbye")
    frame = await echo_client.get_message()
    assert frame.msg_type == picows.WSMsgType.CLOSE
    assert frame.close_code == picows.WSCloseCode.GOING_AWAY
    assert frame.close_message == b"goodbye"
