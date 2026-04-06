import asyncio
import importlib
import os
import pathlib
import ssl
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from logging import getLogger
from typing import Union, Optional

import async_timeout
import pytest

import picows
from picows import ws_create_server, ws_connect

TIMEOUT = 1.0

# Enable picows debug logging for coverage reports
# Also check that all of them are well formatted
getLogger("picows").setLevel(9)


class TestException(Exception):
    pass


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
    winloop = None
    if os.name == "nt":
        # Winloop doesn't work with python 3.9
        if sys.version_info >= (3, 10):
            params = ("asyncio", "winloop")
        else:
            params = ("asyncio", )
        winloop = importlib.import_module("winloop")
    else:
        params = ("asyncio", "uvloop")
        uvloop = importlib.import_module("uvloop")

    @pytest.fixture(params=params)
    def event_loop_policy(request):
        name = request.param

        if name == "asyncio":
            if os.name == "nt":
                if sys.version_info >= (3, 10):
                    return asyncio.DefaultEventLoopPolicy()
                else:
                    return asyncio.WindowsSelectorEventLoopPolicy()
            else:
                return asyncio.DefaultEventLoopPolicy()
        elif name == "uvloop":
            return uvloop.EventLoopPolicy()
        elif name == "winloop":
            return winloop.EventLoopPolicy()
        else:
            raise AssertionError(f"unknown loop: {name!r}")

    return event_loop_policy


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
class Ssl:
    client: Optional[ssl.SSLContext] = None
    server: Optional[ssl.SSLContext] = None


@pytest.fixture(params=["tcp", "ssl"])
def ssl_context(request):
    if request.param == "ssl":
        yield Ssl(create_client_ssl_context(), create_server_ssl_context())
    else:
        yield Ssl()


@pytest.fixture(params=["native", "aiofastnet"])
def use_aiofastnet(request):
    if request.param == "native":
        yield False
    else:
        yield True


@pytest.fixture
async def loop_debug():
    asyncio.get_running_loop().set_debug(True)


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

