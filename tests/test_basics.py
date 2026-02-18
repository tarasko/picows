import asyncio
import base64
import os

import picows
import pytest
import async_timeout

from http import HTTPStatus
from tests.utils import create_client_ssl_context, echo_server, \
    TIMEOUT, AsyncClient, ServerEchoListener, ClientAsyncContext, \
    ServerAsyncContext, get_server_port, multiloop_event_loop_policy, \
    connected_async_client


class MyException(RuntimeError):
    pass


event_loop_policy = multiloop_event_loop_policy()


@pytest.mark.parametrize("msg_size", [0, 1, 2, 3, 4, 5, 6, 7, 8, 29, 64, 256 * 1024, 6*1024*1024])
async def test_echo(connected_async_client, msg_size):
    msg = (b"ABCDEFGHIKLMNOPQ" * (int(msg_size / 16) + 1))[:msg_size]

    connected_async_client.transport.send(picows.WSMsgType.BINARY, msg, False, False)
    frame = await connected_async_client.get_message()
    assert frame.msg_type == picows.WSMsgType.BINARY
    assert frame.payload_as_bytes == msg
    assert frame.payload_as_bytes_from_mv == msg
    assert not frame.fin
    assert not frame.rsv1

    ba = bytearray(b"1234567890123456")
    ba += msg
    connected_async_client.transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, ba, 16)
    frame = await connected_async_client.get_message()
    assert frame.msg_type == picows.WSMsgType.BINARY
    assert frame.payload_as_bytes == msg

    msg = base64.b64encode(msg)
    connected_async_client.transport.send(picows.WSMsgType.TEXT, msg, True, True)
    frame = await connected_async_client.get_message()
    assert frame.msg_type == picows.WSMsgType.TEXT
    assert frame.payload_as_ascii_text == msg.decode("ascii")
    assert frame.payload_as_utf8_text == msg.decode("utf8")
    assert frame.fin
    assert frame.rsv1

    # Check send defaults
    connected_async_client.transport.send(picows.WSMsgType.BINARY, msg)
    frame = await connected_async_client.get_message()
    assert frame.fin
    assert not frame.rsv1

    # Check ping
    connected_async_client.transport.send_ping(b"hi")
    frame = await connected_async_client.get_message()
    assert frame.msg_type == picows.WSMsgType.PING
    assert frame.payload_as_bytes == b"hi"

    # Check pong
    connected_async_client.transport.send_pong(b"hi")
    frame = await connected_async_client.get_message()
    assert frame.msg_type == picows.WSMsgType.PONG
    assert frame.payload_as_bytes == b"hi"

    # Test non-bytes like send
    with pytest.raises(TypeError):
        connected_async_client.transport.send(picows.WSMsgType.BINARY, "hi")


async def test_send_external_bytearray_asserts(connected_async_client):
    with pytest.raises(AssertionError):
        # Check assertion for msg_len >= 0
        connected_async_client.transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, bytearray(b"HELLO"), 16)

    with pytest.raises(AssertionError):
        # Check assertion for offset to be at least 14
        connected_async_client.transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, bytearray(b"1234567890123HELLO"), 13)


async def test_max_frame_size_violation_huge_frame_from_client(echo_server):
    msg = os.urandom(30 * 1024 * 1024)
    async with ClientAsyncContext(AsyncClient, echo_server,
                                  ssl_context=create_client_ssl_context(),
                                  ) as (transport, listener):
        transport.send(picows.WSMsgType.BINARY, msg)
        frame = await listener.get_message()
        assert frame.msg_type == picows.WSMsgType.CLOSE
        assert frame.close_code == picows.WSCloseCode.PROTOCOL_ERROR


async def test_max_frame_size_violation_huge_frame_from_server(echo_server):
    ssl_context = create_client_ssl_context()
    with pytest.raises(picows.WSError, match="violates max allowed size"):
        async with ClientAsyncContext(AsyncClient, echo_server, ssl_context=ssl_context) as (transport, listener):
            async with async_timeout.timeout(1.0):
                transport.send(picows.WSMsgType.TEXT, b"random_30000000")
                await transport.wait_disconnected()

    # Check that the exception persists
    # https://github.com/tarasko/picows/discussions/81
    with pytest.raises(picows.WSError, match="violates max allowed size"):
        async with ClientAsyncContext(AsyncClient, echo_server, ssl_context=ssl_context) as (transport, listener):
            async with async_timeout.timeout(1.0):
                transport.send(picows.WSMsgType.TEXT, b"random_30000000")
                await transport.wait_disconnected()



async def test_close(connected_async_client):
    connected_async_client.transport.send_close(picows.WSCloseCode.GOING_AWAY, b"goodbye")
    frame = await connected_async_client.get_message()
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

        client_reader, client_writer = await asyncio.open_connection("127.0.0.1", get_server_port(server))
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
        url = f"ws://127.0.0.1:{get_server_port(server)}{request_path}"
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
        url = f"ws://127.0.0.1:{get_server_port(server)}/"
        (transport, _) = await picows.ws_connect(picows.WSListener, url, extra_headers=extra_headers)
        transport.disconnect()

        assert request_from_client.headers["User-Agent"] == "picows"
        assert request_from_client.headers["token"] == "abc"
        assert transport.request.headers["User-Agent"] == "picows"
        assert transport.request.headers["token"] == "abc"


async def test_route_not_found():
    server = await picows.ws_create_server(lambda _: None, "127.0.0.1", 0)

    def exc_check(exc):
        return exc.response.status == 404

    async with ServerAsyncContext(server) as server_ctx:
        with pytest.raises(picows.WSError, match="status 101", check=exc_check):
            (_, client) = await picows.ws_connect(picows.WSListener, server_ctx.tcp_url)


async def test_server_internal_error():
    def factory_listener(r):
        raise RuntimeError("oops")

    server = await picows.ws_create_server(factory_listener, "127.0.0.1", 0)

    def exc_check(exc):
        return exc.response.status == 500 and b"oops" in exc.raw_body

    async with ServerAsyncContext(server) as server_ctx:
        with pytest.raises(picows.WSError, match="status 101", check=exc_check):
            (_, client) = await picows.ws_connect(picows.WSListener, server_ctx.tcp_url)


async def test_server_bad_request():
    server = await picows.ws_create_server(lambda _: picows.WSListener(),
                                           "127.0.0.1", 0)

    async with ServerAsyncContext(server):
        r, w = await asyncio.open_connection("127.0.0.1", get_server_port(server))

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
        url = f"ws://127.0.0.1:{get_server_port(server)}/"
        (transport, _) = await picows.ws_connect(picows.WSListener, url)
        transport.disconnect()

        assert transport.response.headers["User-Agent"] == "picows server"


async def test_custom_response_error():
    def factory_listener(r):
        return picows.WSUpgradeResponseWithListener(
            picows.WSUpgradeResponse.create_error_response(HTTPStatus.NOT_FOUND, b"blablabla"), None)

    def exc_check(exc):
        return exc.response.status == HTTPStatus.NOT_FOUND and b"blablabla" in exc.raw_body

    server = await picows.ws_create_server(factory_listener, "127.0.0.1", 0)
    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{get_server_port(server)}/"
        with pytest.raises(picows.WSError, match="status 101", check=exc_check):
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
        (transport, _) = await picows.ws_connect(ClientListener, server_ctx.tcp_url)
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
        (transport, _) = await picows.ws_connect(picows.WSListener, server_ctx.tcp_url)
        async with async_timeout.timeout(TIMEOUT):
            await transport.wait_disconnected()


@pytest.mark.parametrize("disconnect_on_exception", [True, False],
                         ids=["disconnect_on_exception", "no_disconnect_on_exception"])
async def test_ws_on_frame_throw_client_side(disconnect_on_exception):
    class ServerClientListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            transport.send(picows.WSMsgType.BINARY, b"Hello")

    class ClientListener(picows.WSListener):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            raise MyException("exception from client side on_ws_frame")

    server = await picows.ws_create_server(lambda _: ServerClientListener(),
                                           "127.0.0.1",
                                           0)

    async with ServerAsyncContext(server) as server_ctx:
        transport, listener = await picows.ws_connect(ClientListener, server_ctx.tcp_url,
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
        async with ClientAsyncContext(picows.WSListener, server_ctx.tcp_url) as (transport, listener):
            transport.send(picows.WSMsgType.BINARY, b"halo")

            if disconnect_on_exception:
                async with async_timeout.timeout(TIMEOUT):
                    await transport.wait_disconnected()
            else:
                with pytest.raises(asyncio.TimeoutError):
                    async with async_timeout.timeout(TIMEOUT):
                        await transport.wait_disconnected()


async def test_stress(connected_async_client):
    # Heuristic check if picows direct write works smoothly together with
    # loop transport write. We have to fill socket system buffers first
    # and then loop Transport.write kicks in. Only after that we get pause_writing

    connected_async_client.transport.underlying_transport.set_write_buffer_limits(256, 128)

    msg1 = os.urandom(307)
    msg2 = os.urandom(311)
    msg3 = os.urandom(313)

    total_batches = 0
    while not connected_async_client.is_paused:
        connected_async_client.transport.send(picows.WSMsgType.BINARY, msg1)
        connected_async_client.transport.send(picows.WSMsgType.BINARY, msg2)
        connected_async_client.transport.send(picows.WSMsgType.BINARY, msg3)
        total_batches += 1

    # Add extra batch to make sure we utilize loop buffers above high watermark
    connected_async_client.transport.send(picows.WSMsgType.BINARY, msg1)
    connected_async_client.transport.send(picows.WSMsgType.BINARY, msg2)
    connected_async_client.transport.send(picows.WSMsgType.BINARY, msg3)
    total_batches += 1

    for i in range(total_batches * 3):
        async with async_timeout.timeout(TIMEOUT):
            frame = await connected_async_client.get_message()

        if i % 3 == 0:
            assert frame.payload_as_bytes == msg1
        elif i % 3 == 1:
            assert frame.payload_as_bytes == msg2
        else:
            assert frame.payload_as_bytes == msg3

    with pytest.raises(asyncio.TimeoutError):
        async with async_timeout.timeout(TIMEOUT):
            frame = await connected_async_client.get_message()

    assert not connected_async_client.is_paused

