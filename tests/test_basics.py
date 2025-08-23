import asyncio
import base64
import os
import sys

from aiohttp import WSMsgType

import picows
import pytest
import async_timeout

from http import HTTPStatus
from tests.utils import create_client_ssl_context, create_server_ssl_context, \
    ServerAsyncContext, TIMEOUT, \
    materialize_frame, ClientAsyncContext


class MyException(RuntimeError):
    pass


if os.name == 'nt':
    @pytest.fixture(
        params=(
            "asyncio",
        ),
    )
    def event_loop_policy(request):
        if sys.version_info >= (3, 10):
            return asyncio.DefaultEventLoopPolicy()
        else:
            return asyncio.WindowsSelectorEventLoopPolicy()
else:
    import uvloop

    @pytest.fixture(
        params=(
            "asyncio",
            "uvloop",
        ),
    )
    def event_loop_policy(request):
        if request.param == 'asyncio':
            return asyncio.DefaultEventLoopPolicy()
        elif request.param == 'uvloop':
            return uvloop.EventLoopPolicy()
        else:
            assert False, "unknown loop"


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


@pytest.fixture()
async def client_msg_queue(echo_server):
    async with ClientAsyncContext(ClientMsgQueue, echo_server,
                                  ssl_context=create_client_ssl_context(),
                                  websocket_handshake_timeout=0.5,
                                  enable_auto_pong=False
                                  ) as (transport, listener):
        yield listener

        # Teardown client
        transport.send_close(picows.WSCloseCode.GOING_AWAY, b"poka poka")
        # Gracefull shutdown, expect server to disconnect us because we have sent close message
        await transport.wait_disconnected()


@pytest.mark.parametrize("msg_size", [0, 1, 2, 3, 4, 5, 6, 7, 8, 64, 256 * 1024])
async def test_echo(client_msg_queue, msg_size):
    msg = os.urandom(msg_size)
    client_msg_queue.transport.send(picows.WSMsgType.BINARY, msg, False, False)
    frame = await client_msg_queue.get_message()
    assert frame.msg_type == picows.WSMsgType.BINARY
    assert frame.payload_as_bytes == msg
    assert frame.payload_as_bytes_from_mv == msg
    assert not frame.fin
    assert not frame.rsv1

    ba = bytearray(b"1234567890123456")
    ba += msg
    client_msg_queue.transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, ba, 16)
    frame = await client_msg_queue.get_message()
    assert frame.msg_type == picows.WSMsgType.BINARY
    assert frame.payload_as_bytes == msg

    msg = base64.b64encode(msg)
    client_msg_queue.transport.send(picows.WSMsgType.TEXT, msg, True, True)
    frame = await client_msg_queue.get_message()
    assert frame.msg_type == picows.WSMsgType.TEXT
    assert frame.payload_as_ascii_text == msg.decode("ascii")
    assert frame.payload_as_utf8_text == msg.decode("utf8")
    assert frame.fin
    assert frame.rsv1

    # Check send defaults
    client_msg_queue.transport.send(picows.WSMsgType.BINARY, msg)
    frame = await client_msg_queue.get_message()
    assert frame.fin
    assert not frame.rsv1

    # Check ping
    client_msg_queue.transport.send_ping(b"hi")
    frame = await client_msg_queue.get_message()
    assert frame.msg_type == picows.WSMsgType.PING
    assert frame.payload_as_bytes == b"hi"

    # Check pong
    client_msg_queue.transport.send_pong(b"hi")
    frame = await client_msg_queue.get_message()
    assert frame.msg_type == picows.WSMsgType.PONG
    assert frame.payload_as_bytes == b"hi"

    # Test non-bytes like send
    with pytest.raises(TypeError):
        client_msg_queue.transport.send(picows.WSMsgType.BINARY, "hi")


async def test_send_external_bytearray_asserts(client_msg_queue):
    with pytest.raises(AssertionError):
        # Check assertion for msg_len >= 0
        client_msg_queue.transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, bytearray(b"HELLO"), 16)

    with pytest.raises(AssertionError):
        # Check assertion for offset to be at least 14
        client_msg_queue.transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, bytearray(b"1234567890123HELLO"), 13)


async def test_max_frame_size_violation():
    msg = os.urandom(1024 * 1024)
    max_frame_size = 16 * 1024
    server = await picows.ws_create_server(lambda _: ServerEchoListener(),
                                           "127.0.0.1", 0,
                                           max_frame_size=max_frame_size)
    async with ServerAsyncContext(server) as server_ctx:
        async with ClientAsyncContext(ClientMsgQueue, server_ctx.plain_url,
                                      ssl_context=create_client_ssl_context(),
                                      max_frame_size=max_frame_size,
                                      ) as (transport, listener):
            transport.send(picows.WSMsgType.BINARY, msg)
            frame = await listener.get_message()
            assert frame.msg_type == picows.WSMsgType.CLOSE
            assert frame.close_code == picows.WSCloseCode.PROTOCOL_ERROR


async def test_close(client_msg_queue):
    client_msg_queue.transport.send_close(picows.WSCloseCode.GOING_AWAY, b"goodbye")
    frame = await client_msg_queue.get_message()
    assert frame.msg_type == picows.WSMsgType.CLOSE
    assert frame.close_code == picows.WSCloseCode.GOING_AWAY
    assert frame.close_message == b"goodbye"


async def test_client_handshake_timeout(echo_server):
    # Set unreasonably small timeout
    with pytest.raises(asyncio.TimeoutError):
        (_, client) = await picows.ws_connect(picows.WSListener, echo_server,
                                              ssl_context=create_client_ssl_context(),
                                              websocket_handshake_timeout=0.00001)


async def test_server_handshake_timeout():
    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0, websocket_handshake_timeout=0.1)

    async with ServerAsyncContext(server):
        # Give some time for server to start
        await asyncio.sleep(0.1)

        client_reader, client_writer = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
        assert not client_reader.at_eof()
        await asyncio.sleep(0.2)
        assert client_reader.at_eof()


async def test_client_multiple_disconnect(echo_server):
    (transport, _) = await picows.ws_connect(picows.WSListener,
                                             echo_server,
                                             ssl_context=create_client_ssl_context())
    transport.disconnect()
    transport.disconnect()
    transport.disconnect()

    await transport.wait_disconnected()

    (transport, _) = await picows.ws_connect(picows.WSListener,
                                             echo_server,
                                             ssl_context=create_client_ssl_context())

    transport.disconnect(False)
    transport.disconnect(False)
    transport.disconnect(False)

    await transport.wait_disconnected()


@pytest.mark.parametrize("request_path", ["/v1/ws", "/v1/ws?key=blablabla&data=fhhh"])
async def test_request_path_and_params(request_path):
    request_from_client = None

    def listener_factory(request: picows.WSUpgradeRequest):
        nonlocal request_from_client
        request_from_client = request
        return picows.WSListener()

    server = await picows.ws_create_server(listener_factory,
                                           "127.0.0.1", 0, websocket_handshake_timeout=0.1)
    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}{request_path}"
        (transport, _) = await picows.ws_connect(picows.WSListener, url)
        transport.disconnect()

        assert request_from_client.method == b"GET"
        assert request_from_client.path == request_path.encode()
        assert request_from_client.version == b"HTTP/1.1"

        assert transport.request.method == b"GET"
        assert transport.request.path == request_path.encode()
        assert transport.request.version == b"HTTP/1.1"

        assert transport.response.version == b"HTTP/1.1"
        assert transport.response.status == HTTPStatus.SWITCHING_PROTOCOLS


@pytest.mark.parametrize("extra_headers", [
    {"User-Agent": "picows", "Token": "abc"},
    [("User-Agent", "picows"), ("Token", "abc")]
])
async def test_client_extra_headers(extra_headers):
    request_from_client = None

    def listener_factory(request: picows.WSUpgradeRequest):
        nonlocal request_from_client
        request_from_client = request
        return picows.WSListener()

    server = await picows.ws_create_server(listener_factory,
                                           "127.0.0.1", 0,
                                           websocket_handshake_timeout=0.1)
    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/"
        (transport, _) = await picows.ws_connect(picows.WSListener, url, extra_headers=extra_headers)
        transport.disconnect()

        assert request_from_client.headers["User-Agent"] == "picows"
        assert request_from_client.headers["token"] == "abc"
        assert transport.request.headers["User-Agent"] == "picows"
        assert transport.request.headers["token"] == "abc"


async def test_route_not_found():
    server = await picows.ws_create_server(lambda _: None, "127.0.0.1", 0)
    async with ServerAsyncContext(server) as server_ctx:
        with pytest.raises(picows.WSError, match="404 Not Found"):
            (_, client) = await picows.ws_connect(picows.WSListener, server_ctx.plain_url)


async def test_server_internal_error():
    def factory_listener(r):
        raise RuntimeError("oops")

    server = await picows.ws_create_server(factory_listener, "127.0.0.1", 0)
    async with ServerAsyncContext(server) as server_ctx:
        with pytest.raises(picows.WSError, match="500 Internal Server Error"):
            (_, client) = await picows.ws_connect(picows.WSListener, server_ctx.plain_url)


async def test_server_bad_request():
    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0)

    async with ServerAsyncContext(server):
        r, w = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])

        w.write(b"zzzz\r\nasdfasdf\r\n\r\n")
        resp_header = await r.readuntil(b"\r\n\r\n")
        assert b"400 Bad Request" in resp_header
        async with async_timeout.timeout(TIMEOUT):
            await r.read()
        assert r.at_eof()


async def test_custom_response():
    def factory_listener(r):
        extra_headers = {"User-Agent": "picows server"}
        return picows.WSUpgradeResponseWithListener(
            picows.WSUpgradeResponse.create_101_response(extra_headers), picows.WSListener())

    server = await picows.ws_create_server(factory_listener, "127.0.0.1", 0)
    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/"
        (transport, _) = await picows.ws_connect(picows.WSListener, url)
        transport.disconnect()

        assert transport.response.headers["User-Agent"] == "picows server"


async def test_custom_response_error():
    def factory_listener(r):
        return picows.WSUpgradeResponseWithListener(
            picows.WSUpgradeResponse.create_error_response(HTTPStatus.NOT_FOUND, b"blablabla"), None)

    server = await picows.ws_create_server(factory_listener, "127.0.0.1", 0)
    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/"
        with pytest.raises(picows.WSError, match="blablabla"):
            (transport, _) = await picows.ws_connect(picows.WSListener, url)


async def test_ws_on_connected_throw_client_side():
    # Check that client side, initiate disconnect(no timeouts on wait_disconnected) and
    # transfer exception to wait_disconnected
    class ClientListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            raise MyException("exception from client side on_ws_connected")

    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0)
    async with ServerAsyncContext(server) as server_ctx:
        (transport, _) = await picows.ws_connect(ClientListener, server_ctx.plain_url)
        async with async_timeout.timeout(TIMEOUT):
            with pytest.raises(MyException):
                await transport.wait_disconnected()


async def test_ws_on_connected_throw_server_side():
    # Check that server side initiate disconnect(no timeouts on wait_disconnected) and
    # swallow exception
    class ServerClientListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            raise MyException("exception from server side on_ws_connected")

    server = await picows.ws_create_server(lambda _: ServerClientListener(),
                                           "127.0.0.1", 0)
    async with ServerAsyncContext(server) as server_ctx:
        (transport, _) = await picows.ws_connect(picows.WSListener, server_ctx.plain_url)
        async with async_timeout.timeout(TIMEOUT):
            await transport.wait_disconnected()


@pytest.mark.parametrize("disconnect_on_exception", [True, False],
                         ids=["disconnect_on_exception", "no_disconnect_on_exception"])
async def test_ws_on_frame_throw_client_side(disconnect_on_exception):
    class ServerClientListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            transport.send(WSMsgType.BINARY, b"Hello")

    class ClientListener(picows.WSListener):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            raise MyException("exception from client side on_ws_frame")

    server = await picows.ws_create_server(lambda _: ServerClientListener(),
                                           "127.0.0.1",
                                           0)

    async with ServerAsyncContext(server) as server_ctx:
        transport, listener = await picows.ws_connect(ClientListener, server_ctx.plain_url,
                                                      disconnect_on_exception=disconnect_on_exception)
        try:
            if disconnect_on_exception:
                with pytest.raises(MyException):
                    async with async_timeout.timeout(TIMEOUT):
                        await transport.wait_disconnected()
            else:
                with pytest.raises(asyncio.TimeoutError):
                    async with async_timeout.timeout(TIMEOUT):
                        await transport.wait_disconnected()
        finally:
            transport.disconnect(False)


@pytest.mark.parametrize("disconnect_on_exception", [True, False],
                         ids=["disconnect_on_exception", "no_disconnect_on_exception"])
async def test_ws_on_frame_throw_server_side(disconnect_on_exception):
    class ServerClientListener(picows.WSListener):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            raise MyException("exception from server side on_ws_frame")

    server = await picows.ws_create_server(lambda _: ServerClientListener(),
                                           "127.0.0.1",
                                           0,
                                           disconnect_on_exception=disconnect_on_exception)

    async with ServerAsyncContext(server) as server_ctx:
        async with ClientAsyncContext(picows.WSListener, server_ctx.plain_url) as (transport, listener):
            transport.send(picows.WSMsgType.BINARY, b"halo")

            if disconnect_on_exception:
                async with async_timeout.timeout(TIMEOUT):
                    await transport.wait_disconnected()
            else:
                with pytest.raises(asyncio.TimeoutError):
                    async with async_timeout.timeout(TIMEOUT):
                        await transport.wait_disconnected()


async def test_stress(client_msg_queue):
    # Heuristic check if picows direct write works smoothly together with
    # loop transport write. We have to fill socket system buffers first
    # and then loop Transport.write kicks in. Only after that we get pause_writing

    client_msg_queue.transport.underlying_transport.set_write_buffer_limits(256, 128)

    msg1 = os.urandom(307)
    msg2 = os.urandom(311)
    msg3 = os.urandom(313)

    total_batches = 0
    while not client_msg_queue.is_paused:
        client_msg_queue.transport.send(picows.WSMsgType.BINARY, msg1)
        client_msg_queue.transport.send(picows.WSMsgType.BINARY, msg2)
        client_msg_queue.transport.send(picows.WSMsgType.BINARY, msg3)
        total_batches += 1

    # Add extra batch to make sure we utilize loop buffers above high watermark
    client_msg_queue.transport.send(picows.WSMsgType.BINARY, msg1)
    client_msg_queue.transport.send(picows.WSMsgType.BINARY, msg2)
    client_msg_queue.transport.send(picows.WSMsgType.BINARY, msg3)
    total_batches += 1

    for i in range(total_batches * 3):
        async with async_timeout.timeout(TIMEOUT):
            frame = await client_msg_queue.get_message()

        if i % 3 == 0:
            assert frame.payload_as_bytes == msg1
        elif i % 3 == 1:
            assert frame.payload_as_bytes == msg2
        else:
            assert frame.payload_as_bytes == msg3

    with pytest.raises(asyncio.TimeoutError):
        async with async_timeout.timeout(TIMEOUT):
            frame = await client_msg_queue.get_message()

    assert not client_msg_queue.is_paused
