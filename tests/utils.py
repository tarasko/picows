import asyncio
import importlib
import os
import pathlib
import ssl
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Union, Optional

import async_timeout
import pytest

import picows

TIMEOUT = 1.0


def _default_windows_policy() -> asyncio.AbstractEventLoopPolicy:
    # Matches your current logic
    if sys.version_info >= (3, 10):
        return asyncio.DefaultEventLoopPolicy()
    return asyncio.WindowsSelectorEventLoopPolicy()

def multiloop_event_loop_policy():
    """
    Returns a pytest fixture function named `event_loop_policy` (by assignment in the test module).

    Usage in a test module:
        from tests.utils import make_event_loop_policy_fixture
        event_loop_policy = make_event_loop_policy_fixture()

    Notes:
    - On Windows, uvloop isn't used (by default) and we return the appropriate asyncio policy.
    - On non-Windows, params are ("asyncio", "uvloop")
    """
    # Decide params at factory creation time (import-time for that module)
    uvloop = None
    if os.name == "nt":
        params = ("asyncio",)
    else:
        params = ("asyncio", "uvloop")
        uvloop = importlib.import_module("uvloop")

    @pytest.fixture(params=params)
    def event_loop_policy(request) -> asyncio.AbstractEventLoopPolicy:
        name = request.param

        if os.name == "nt":
            # only asyncio param
            return _default_windows_policy()

        # non-Windows
        if name == "asyncio":
            return asyncio.DefaultEventLoopPolicy()
        elif name == "uvloop":
            return uvloop.EventLoopPolicy()
        else:
            raise AssertionError(f"unknown loop: {name!r}")

    return event_loop_policy


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


class AsyncClient(picows.WSListener):
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
class ServerUrls:
    tcp_url: Optional[str]
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
        await server.__aexit__()
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


@pytest.fixture()
async def connected_async_client(echo_server):
    async with ClientAsyncContext(AsyncClient, echo_server,
                                  ssl_context=create_client_ssl_context(),
                                  websocket_handshake_timeout=0.5,
                                  enable_auto_pong=False
                                  ) as (transport, listener):
        yield listener

        # Teardown client
        transport.send_close(picows.WSCloseCode.GOING_AWAY, b"poka poka")
        # Gracefull shutdown, expect server to disconnect us because we have sent close message
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


@pytest.fixture(params=["tcp", "ssl"])
async def echo_server(request):
    use_ssl = request.param == "ssl"
    server = await picows.ws_create_server(lambda _: ServerEchoListener(),
                                           "127.0.0.1",
                                           0,
                                           ssl=create_server_ssl_context() if use_ssl else None,
                                           websocket_handshake_timeout=0.5,
                                           enable_auto_pong=False)

    async with ServerAsyncContext(server) as server_ctx:
        yield server_ctx.ssl_url if use_ssl else server_ctx.tcp_url


