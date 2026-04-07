import asyncio
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Union

import async_timeout

import picows
from picows import ws_create_server, ws_connect

TIMEOUT = 1.0


class TestException(Exception):
    pass


class BinaryFrame:
    def __init__(self, frame: picows.WSFrame):
        self.frame_str = str(frame)
        self.msg_type = frame.msg_type
        self.payload_as_bytes = frame.get_payload_as_bytes()
        self.payload_as_bytes_from_mv = bytes(frame.get_payload_as_memoryview())
        self.fin = frame.fin
        self.rsv1 = frame.rsv1


class TextFrame:
    def __init__(self, frame: picows.WSFrame):
        self.frame_str = str(frame)
        self.msg_type = frame.msg_type
        self.payload_as_ascii_text = frame.get_payload_as_ascii_text()
        self.payload_as_utf8_text = frame.get_payload_as_utf8_text()
        self.fin = frame.fin
        self.rsv1 = frame.rsv1


class CloseFrame:
    def __init__(self, frame: picows.WSFrame):
        self.frame_str = str(frame)
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


class AsyncClient(picows.WSListener):
    transport: picows.WSTransport
    msg_queue: asyncio.Queue
    is_paused: bool

    def on_ws_connected(self, transport: picows.WSTransport):
        self.transport = transport
        peercert = transport.underlying_transport.get_extra_info('peercert')
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

    async def get_message_no_timeout(self):
        item = await self.msg_queue.get()
        self.msg_queue.task_done()
        return item


class ServerEchoListener(picows.WSListener):
    # Standard echo server that is used for testing
    # Send back received BINARY, CLOSE, CONTINUATION frames.
    # On TEXT frame, analyze content:
    # * disconnect_me_without_close_frame - disconnect client immediately
    # * random_1024 - generate random message of 1024 bytes and send it as BINARY
    # * everything else is just echoed as TEXT frame
    def on_ws_connected(self, transport: picows.WSTransport):
        self._transport = transport

    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        if frame.msg_type == picows.WSMsgType.CLOSE:
            self._transport.send_close(frame.get_close_code(), frame.get_close_message())
            self._transport.disconnect()
            return

        if frame.msg_type == picows.WSMsgType.TEXT:
            if frame.get_payload_as_memoryview() == b"disconnect_me_without_close_frame":
                self._transport.disconnect()
                return

            # Check if client wants us to send a random message of a specific size
            if frame.get_payload_as_memoryview()[:8].tobytes().startswith(b"random_"):
                data = frame.get_payload_as_ascii_text()
                msg_size = int(data.removeprefix("random_"))
                msg = os.urandom(msg_size)
                self._transport.send(picows.WSMsgType.BINARY, msg)
                return

        self._transport.send(frame.msg_type, frame.get_payload_as_bytes(), frame.fin, frame.rsv1)


@dataclass
class WSServerInfo:
    url: str
    host: str
    port: int


@asynccontextmanager
async def WSServer(protocol_factory=None, **kwargs):
    if protocol_factory is None:
        protocol_factory = lambda _: ServerEchoListener()

    if kwargs.get('websocket_handshake_timeout') is None:
        kwargs['websocket_handshake_timeout'] = 0.5

    if kwargs.get('enable_auto_pong') is None:
        kwargs['enable_auto_pong'] = False

    ssl = kwargs.get("ssl")
    server = await ws_create_server(protocol_factory, "127.0.0.1", 0, **kwargs)
    resolved_port = server.sockets[0].getsockname()[1]
    try:
        yield WSServerInfo(f"{'wss' if ssl else 'ws'}://127.0.0.1:{resolved_port}/", "127.0.0.1", resolved_port)
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def WSClient(server, listener_factory=None, **kwargs):
    if isinstance(server, WSServerInfo):
        url = server.url
    else:
        url = server

    if listener_factory is None:
        listener_factory = lambda: AsyncClient()

    if kwargs.get('websocket_handshake_timeout') is None:
        kwargs['websocket_handshake_timeout'] = 0.5

    if kwargs.get('enable_auto_pong') is None:
        kwargs['enable_auto_pong'] = False

    transport, listener = await ws_connect(listener_factory, url, **kwargs)
    try:
        yield listener
    finally:
        transport.disconnect(False)
        try:
            await transport.wait_disconnected()
        except TestException:
            pass

