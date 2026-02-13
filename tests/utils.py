import asyncio
import pathlib
import ssl
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Union, Optional

import async_timeout
import pytest

import picows

TIMEOUT = 0.5


class BinaryFrame:
    def __init__(self, frame: picows.WSFrame):
        self.msg_type = frame.msg_type
        self.payload_as_bytes = frame.get_payload_as_bytes()
        self.payload_as_bytes_from_mv = bytes(frame.get_payload_as_memoryview())
        self.fin = frame.fin
        self.rsv1 = frame.rsv1


class TextFrame:
    def __init__(self, frame: picows.WSFrame):
        self.msg_type = frame.msg_type
        self.payload_as_ascii_text = frame.get_payload_as_ascii_text()
        self.payload_as_utf8_text = frame.get_payload_as_utf8_text()
        self.fin = frame.fin
        self.rsv1 = frame.rsv1


class CloseFrame:
    def __init__(self, frame: picows.WSFrame):
        self.msg_type = frame.msg_type
        self.close_code = frame.get_close_code()
        self.close_message = frame.get_close_message()
        self.fin = frame.fin
        self.rsv1 = frame.rsv1


def materialize_frame(frame: picows.WSFrame) -> Union[TextFrame, CloseFrame, BinaryFrame]:
    if frame.msg_type == picows.WSMsgType.TEXT:
        return TextFrame(frame)
    elif frame.msg_type == picows.WSMsgType.CLOSE:
        return CloseFrame(frame)
    else:
        return BinaryFrame(frame)


class ClientMsgQueue(picows.WSListener):
    transport: picows.WSTransport
    msg_queue: asyncio.Queue
    is_paused: bool

    def on_ws_connected(self, transport: picows.WSTransport):
        self.transport = transport
        self.msg_queue = asyncio.Queue()
        self.is_paused = False

    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        self.msg_queue.put_nowait(materialize_frame(frame))

    def pause_writing(self):
        self.is_paused = True

    def resume_writing(self):
        self.is_paused = False

    async def get_message(self, timeout=TIMEOUT):
        async with async_timeout.timeout(timeout):
            item = await self.msg_queue.get()
            self.msg_queue.task_done()
            return item


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


@dataclass
class ServerUrls:
    plain_url: Optional[str]
    ssl_url: Optional[str]


@asynccontextmanager
async def ServerAsyncContext(server, shutdown_timeout=TIMEOUT):
    server_task = asyncio.create_task(server.serve_forever())
    await server.__aenter__()
    try:
        yield ServerUrls(f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}",
                         f"wss://127.0.0.1:{server.sockets[0].getsockname()[1]}")
    finally:
        server_task.cancel()
        server.__aexit__()
        with pytest.raises(asyncio.CancelledError):
            async with async_timeout.timeout(shutdown_timeout):
                await server_task


@asynccontextmanager
async def ClientAsyncContext(*args, **kwargs):
    transport, listener = await picows.ws_connect(*args, **kwargs)
    try:
        yield (transport, listener)
    finally:
        transport.disconnect(graceful=False)
        await transport.wait_disconnected()


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


def get_server_port(server: asyncio.Server):
    return server.sockets[0].getsockname()[1]


@pytest.fixture(params=["plain", "ssl"])
async def echo_server(request):
    use_ssl = request.param == "ssl"
    server = await picows.ws_create_server(lambda _: ServerEchoListener(),
                                           "127.0.0.1",
                                           0,
                                           ssl=create_server_ssl_context() if use_ssl else None,
                                           websocket_handshake_timeout=0.5,
                                           enable_auto_pong=False)

    async with ServerAsyncContext(server) as server_ctx:
        yield server_ctx.ssl_url if use_ssl else server_ctx.plain_url
