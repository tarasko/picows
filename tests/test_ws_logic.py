import asyncio
import base64
import logging
import os
import struct
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from hashlib import sha1
from http import HTTPStatus

import async_timeout
import pytest

import picows
from picows.api import _resolve_logger
from tests.utils import WSServer, WSClient, AsyncClient, TIMEOUT
from tests.fixtures import use_aiofastnet, ssl_context


@asynccontextmanager
async def raw_handshake_server(response: bytes):
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"ws://127.0.0.1:{port}/"
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def delayed_handshake_server(delay: float):
    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        request = await reader.readuntil(b"\r\n\r\n")
        websocket_key = next(
            line.split(b":", 1)[1].strip()
            for line in request.split(b"\r\n")
            if line.lower().startswith(b"sec-websocket-key:")
        )
        accept = base64.b64encode(
            sha1(websocket_key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
        )
        await asyncio.sleep(delay)
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n"
            b"\r\n"
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"ws://127.0.0.1:{port}/"
    finally:
        server.close()
        await server.wait_closed()


async def test_send_external_bytearray_asserts():
    async with WSServer() as server:
        async with WSClient(server) as client:
            with pytest.raises(ValueError):
                # Check assertion for msg_len >= 0
                client.transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, bytearray(b"HELLO"), 16)

            with pytest.raises(ValueError):
                # Check assertion for offset to be at least 14
                client.transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, bytearray(b"1234567890123HELLO"), 13)


async def test_max_frame_size_violation_huge_frame_from_client(use_aiofastnet, ssl_context):
    msg = os.urandom(128 * 1024)
    async with WSServer(ssl=ssl_context.server, use_aiofastnet=use_aiofastnet, max_frame_size=64*1024) as server:
        async with WSClient(server, ssl_context=ssl_context.client, use_aiofastnet=use_aiofastnet) as client:
            client.transport.send(picows.WSMsgType.BINARY, msg)
            frame = await client.get_message()
            assert frame.msg_type == picows.WSMsgType.CLOSE
            assert frame.close_code == picows.WSCloseCode.MESSAGE_TOO_BIG


async def test_max_frame_size_violation_huge_frame_from_server(use_aiofastnet, ssl_context):
    async with WSServer(ssl=ssl_context.server, use_aiofastnet=use_aiofastnet) as server:
        with pytest.raises(picows.WSError, match="Received frame with payload size exceeding max allowed size"):
            async with WSClient(server, ssl_context=ssl_context.client, use_aiofastnet=use_aiofastnet, max_frame_size=64*1024) as client:
                client.transport.send(picows.WSMsgType.TEXT, b"random_100000")
                async with async_timeout.timeout(1.0):
                    await client.transport.wait_disconnected()


@pytest.mark.parametrize("request_path", ["/v1/ws", "/v1/ws?key=blablabla&data=fhhh"])
async def test_request_path_and_params(request_path):
    def listener_factory(request: picows.WSUpgradeRequest):
        nonlocal request_from_client
        request_from_client = request
        return picows.WSListener()

    request_from_client = None

    async with WSServer(listener_factory) as server:
        url = f"ws://127.0.0.1:{server.port}{request_path}"
        async with WSClient(url) as client:
            assert request_from_client.method == b"GET"
            assert request_from_client.path == request_path.encode()
            assert request_from_client.version == b"HTTP/1.1"

            assert client.transport.request.method == b"GET"
            assert client.transport.request.path == request_path.encode()
            assert client.transport.request.version == b"HTTP/1.1"

            assert client.transport.response.version == b"HTTP/1.1"
            assert client.transport.response.status == HTTPStatus.SWITCHING_PROTOCOLS


async def test_route_not_found():
    def exc_check(exc):
        return exc.response.status == 404

    async with WSServer((lambda _: None)) as server:
        with pytest.raises(picows.WSError, match="status 101", check=exc_check):
            async with WSClient(server) as client:
                pass



async def test_server_internal_error():
    def exc_check(exc):
        return exc.response.status == 500 and b"oops" in exc.raw_body

    def factory_listener(r):
        raise RuntimeError("oops")

    async with WSServer(factory_listener) as server:
        with pytest.raises(picows.WSError, match="status 101", check=exc_check):
            async with WSClient(server) as client:
                pass


async def test_server_bad_request():
    async with WSServer() as server:
        r, w = await asyncio.open_connection(server.host, server.port)

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

    async with WSServer(factory_listener) as server:
        async with WSClient(server) as client:
            assert client.transport.response.headers["User-Agent"] == "picows server"


async def test_custom_response_error():
    def exc_check(exc):
        return exc.response.status == HTTPStatus.NOT_FOUND and b"blablabla" in exc.raw_body

    def factory_listener(r):
        return picows.WSUpgradeResponseWithListener(
            picows.WSUpgradeResponse.create_error_response(HTTPStatus.NOT_FOUND, b"blablabla"), None)

    async with WSServer(factory_listener) as server:
        with pytest.raises(picows.WSError, match="status 101", check=exc_check):
            async with WSClient(server) as client:
                pass


async def test_invalid_frame_opcode():
    async with WSServer() as server:
        async with WSClient(server) as client:
            client.transport.send(0x4, None)
            frame = await client.get_message()
            assert frame.msg_type == picows.WSMsgType.CLOSE
            assert frame.close_code == picows.WSCloseCode.PROTOCOL_ERROR
            assert b"Received frame with invalid opcode" in frame.close_message
            await client.transport.wait_disconnected()


async def test_unmasked_frame_from_client():
    async with WSServer() as server:
        async with WSClient(server) as client:
            empty_unmasked_bin_frame = struct.pack("!BB", 0x82, 0x00)
            client.transport.underlying_transport.write(empty_unmasked_bin_frame)
            frame = await client.get_message()
            assert frame.msg_type == picows.WSMsgType.CLOSE
            assert frame.close_code == picows.WSCloseCode.PROTOCOL_ERROR
            assert b"Received un-masked frame from client" in frame.close_message
            await client.transport.wait_disconnected()


async def test_masked_frame_from_server():
    class ServerClientListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            empty_masked_bin_frame = struct.pack("!BBI", 0x82, 0x80, 0x12345678)
            transport.underlying_transport.write(empty_masked_bin_frame)

    async with WSServer(lambda _: ServerClientListener()) as server:
        async with WSClient(server) as client:
            with pytest.raises(picows.WSProtocolError, match="Received masked frame from server"):
                await client.transport.wait_disconnected()


async def test_close_frame_invalid_utf8_reason_from_client():
    async with WSServer() as server:
        async with WSClient(server) as client:
            mask = 0x12345678
            payload = struct.pack("!H", picows.WSCloseCode.OK) + b"\xff"
            masked_payload = bytes(
                b ^ mask.to_bytes(4, "big")[i % 4]
                for i, b in enumerate(payload)
            )
            invalid_close_frame = struct.pack("!BBI", 0x88, 0x80 | len(payload), mask) + masked_payload

            client.transport.underlying_transport.write(invalid_close_frame)
            frame = await client.get_message()
            assert frame.msg_type == picows.WSMsgType.CLOSE
            assert frame.close_code == picows.WSCloseCode.INVALID_TEXT
            assert b"Received CLOSE with invalid UTF-8 reason" in frame.close_message
            await client.transport.wait_disconnected()

            assert client.transport.close_handshake.sent is None
            assert client.transport.close_handshake.recv.code == picows.WSCloseCode.INVALID_TEXT
            assert client.transport.close_handshake.recv.reason == "Received CLOSE with invalid UTF-8 reason"
            assert client.transport.close_handshake.recv_then_sent is True


async def test_close_handshake_client_initiates_close():
    server_transport = None

    class ServerListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            nonlocal server_transport
            server_transport = transport

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.CLOSE:
                transport.send_close(frame.get_close_code(), frame.get_close_message())
                transport.disconnect()

    async with WSServer(lambda _: ServerListener()) as server:
        async with WSClient(server) as client:
            client.transport.send_close(picows.WSCloseCode.OK, b"client says bye")
            await client.transport.wait_disconnected()

            assert client.transport.close_handshake.sent.code == picows.WSCloseCode.OK
            assert client.transport.close_handshake.sent.reason == "client says bye"
            assert client.transport.close_handshake.recv.code == picows.WSCloseCode.OK
            assert client.transport.close_handshake.recv.reason == "client says bye"
            assert client.transport.close_handshake.recv_then_sent is False

            assert server_transport.close_handshake.sent.code == picows.WSCloseCode.OK
            assert server_transport.close_handshake.sent.reason == "client says bye"
            assert server_transport.close_handshake.recv.code == picows.WSCloseCode.OK
            assert server_transport.close_handshake.recv.reason == "client says bye"
            assert server_transport.close_handshake.recv_then_sent is True


async def test_close_handshake_server_initiates_close():
    server_transport = None

    class ServerListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            nonlocal server_transport
            server_transport = transport
            transport.send_close(picows.WSCloseCode.GOING_AWAY, b"server shutdown")
            asyncio.get_running_loop().call_later(0.05, transport.disconnect)

    class ClientListener(AsyncClient):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.CLOSE:
                transport.send_close(frame.get_close_code(), frame.get_close_message())
            else:
                super().on_ws_frame(transport, frame)

    async with WSServer(lambda _: ServerListener()) as server:
        async with WSClient(server, ClientListener) as client:
            await client.transport.wait_disconnected()
            assert client.transport.close_handshake.recv.code == picows.WSCloseCode.GOING_AWAY
            assert client.transport.close_handshake.recv.reason == "server shutdown"
            assert client.transport.close_handshake.sent.code == picows.WSCloseCode.GOING_AWAY
            assert client.transport.close_handshake.sent.reason == "server shutdown"
            assert client.transport.close_handshake.recv_then_sent is True

            assert server_transport.close_handshake.recv.code == picows.WSCloseCode.GOING_AWAY
            assert server_transport.close_handshake.recv.reason == "server shutdown"
            assert server_transport.close_handshake.sent.code == picows.WSCloseCode.GOING_AWAY
            assert server_transport.close_handshake.sent.reason == "server shutdown"
            assert server_transport.close_handshake.recv_then_sent is False


async def test_close_handshake_client_initiates_close_server_disconnects_without_reply():
    server_transport = None

    class ServerListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            nonlocal server_transport
            server_transport = transport

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.CLOSE:
                transport.disconnect(False)

    async with WSServer(lambda _: ServerListener()) as server:
        async with WSClient(server) as client:
            client.transport.send_close(picows.WSCloseCode.OK, b"client says bye")
            await client.transport.wait_disconnected()

            assert client.transport.close_handshake.recv is None
            assert client.transport.close_handshake.sent.code == picows.WSCloseCode.OK
            assert client.transport.close_handshake.sent.reason == "client says bye"
            assert client.transport.close_handshake.recv_then_sent is False

            assert server_transport.close_handshake.recv.code == picows.WSCloseCode.OK
            assert server_transport.close_handshake.recv.reason == "client says bye"
            assert server_transport.close_handshake.sent is None
            assert server_transport.close_handshake.recv_then_sent is True


async def test_close_handshake_server_initiates_close_client_disconnects_without_reply():
    server_transport = None

    class ServerListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            nonlocal server_transport
            server_transport = transport
            transport.send_close(picows.WSCloseCode.GOING_AWAY, b"server shutdown")
            asyncio.get_running_loop().call_later(0.05, transport.disconnect)

    class ClientListener(AsyncClient):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            super().on_ws_frame(transport, frame)
            if frame.msg_type == picows.WSMsgType.CLOSE:
                transport.disconnect(False)

    async with WSServer(lambda _: ServerListener()) as server:
        async with WSClient(server, ClientListener) as client:
            await client.transport.wait_disconnected()

            assert client.transport.close_handshake.recv.code == picows.WSCloseCode.GOING_AWAY
            assert client.transport.close_handshake.recv.reason == "server shutdown"
            assert client.transport.close_handshake.sent is None
            assert client.transport.close_handshake.recv_then_sent is True

            assert server_transport.close_handshake.recv is None
            assert server_transport.close_handshake.sent.code == picows.WSCloseCode.GOING_AWAY
            assert server_transport.close_handshake.sent.reason == "server shutdown"
            assert server_transport.close_handshake.recv_then_sent is False


async def test_wrong_thread_assert():
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1) as executor:
        async with WSServer() as server:
            async with WSClient(server) as client:
                msg = b"ABCDEFGHIKLMNOPQ"
                msg_ba = bytearray(b"asasdfbasdfbaskjdfasd")

                with pytest.raises(RuntimeError, match="WSTransport.send called from a wrong thread"):
                    await loop.run_in_executor(executor, client.transport.send, picows.WSMsgType.BINARY, msg)

                with pytest.raises(RuntimeError, match="WSTransport.send_ping called from a wrong thread"):
                    await loop.run_in_executor(executor, client.transport.send_ping)

                with pytest.raises(RuntimeError, match="WSTransport.send_pong called from a wrong thread"):
                    await loop.run_in_executor(executor, client.transport.send_pong)

                with pytest.raises(RuntimeError, match="WSTransport.send_close called from a wrong thread"):
                    await loop.run_in_executor(executor, client.transport.send_close)

                with pytest.raises(RuntimeError, match="WSTransport.send_reuse_external_bytearray called from a wrong thread"):
                    await loop.run_in_executor(executor, client.transport.send_reuse_external_bytearray, picows.WSMsgType.BINARY, msg_ba, 14)

                with pytest.raises(RuntimeError, match="WSTransport.disconnect called from a wrong thread"):
                    await loop.run_in_executor(executor, client.transport.disconnect)


async def test_handshake_invalid_status_error():
    response = (
        b"HTTP/1.1 404 Not Found\r\n"
        b"Connection: close\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    async with raw_handshake_server(response) as url:
        with pytest.raises(picows.WSInvalidStatusError):
            await picows.ws_connect(AsyncClient, url)


async def test_handshake_invalid_upgrade_error():
    response = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: not-websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: invalid\r\n"
        b"\r\n"
    )
    async with raw_handshake_server(response) as url:
        with pytest.raises(picows.WSInvalidUpgradeError, match="invalid upgrade header"):
            await picows.ws_connect(AsyncClient, url)


async def test_handshake_invalid_message_error():
    response = (
        b"NOT-HTTP\r\n"
        b"Header: value\r\n"
        b"\r\n"
    )
    async with raw_handshake_server(response) as url:
        with pytest.raises(picows.WSInvalidMessageError):
            await picows.ws_connect(AsyncClient, url)


async def test_client_handshake_timeout_none():
    async with delayed_handshake_server(0.2) as url:
        transport, _ = await picows.ws_connect(
            AsyncClient,
            url,
            websocket_handshake_timeout=None,
        )
        transport.disconnect(False)
        await transport.wait_disconnected()


async def test_server_handshake_timeout_none():
    server = await picows.ws_create_server(
        lambda _: picows.WSListener(),
        "127.0.0.1",
        0,
        websocket_handshake_timeout=None,
    )
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.2)
        assert not reader.at_eof()
        writer.write(
            b"GET / HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 13\r\n"
            b"\r\n"
        )
        response = await reader.readuntil(b"\r\n\r\n")
        assert b"101 Switching Protocols" in response
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


def test_resolve_logger():
    logger = logging.getLogger("tests.picows.custom")

    assert _resolve_logger(None, "client") is logging.getLogger("picows.client")
    assert _resolve_logger(None, "server") is logging.getLogger("picows.server")
    assert _resolve_logger("custom", "client") is logging.getLogger("picows.custom")
    assert _resolve_logger(logger, "client") is logger
