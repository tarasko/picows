import asyncio
import base64
import os
import pathlib
import ssl

import picows
import pytest
import async_timeout


TIMEOUT = 0.5


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


class ServerAsyncContext:
    def __init__(self, server):
        self.server = server
        self.server_task = asyncio.create_task(server.serve_forever())

    async def __aenter__(self):
        return self.server

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.server.close()
        await self.server.wait_closed()


@pytest.fixture(params=[False, True])
async def echo_server(request):
    class PicowsServerListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            self._transport = transport

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.CLOSE:
                self._transport.send_close(frame.get_close_code(), frame.get_close_message())
                self._transport.disconnect()
            else:
                self._transport.send(frame.msg_type, frame.get_payload_as_bytes(), frame.fin, frame.rsv1)

    use_ssl = request.param
    server = await picows.ws_create_server(lambda _: PicowsServerListener(),
                                           "127.0.0.1",
                                           0,
                                           ssl=create_server_ssl_context() if use_ssl else None,
                                           websocket_handshake_timeout=0.5)

    async with ServerAsyncContext(server):
        yield f"{'wss' if use_ssl else 'ws'}://127.0.0.1:{server.sockets[0].getsockname()[1]}/"


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
            async with async_timeout.timeout(TIMEOUT):
                return await self.msg_queue.get()

    (_, client) = await picows.ws_connect(PicowsClientListener, echo_server,
                                          ssl_context=create_client_ssl_context(),
                                          websocket_handshake_timeout=0.5)
    yield client

    # Teardown client
    client.transport.send_close(picows.WSCloseCode.GOING_AWAY, b"poka poka")
    try:
        # Gracefull shutdown, expect server to disconnect us because we have sent close message
        async with async_timeout.timeout(TIMEOUT):
            await client.transport.wait_disconnected()
    finally:
        client.transport.disconnect()


@pytest.mark.parametrize("msg_size", [256, 256 * 1024])
async def test_echo(echo_client, msg_size):
    msg = os.urandom(msg_size)
    echo_client.transport.send(picows.WSMsgType.BINARY, msg, False, False)
    async with async_timeout.timeout(TIMEOUT):
        frame = await echo_client.get_message()
    assert frame.msg_type == picows.WSMsgType.BINARY
    assert frame.payload_as_bytes == msg
    assert frame.payload_as_bytes_from_mv == msg
    assert not frame.fin
    assert not frame.rsv1

    msg = base64.b64encode(msg)
    echo_client.transport.send(picows.WSMsgType.TEXT, msg, True, True)
    async with async_timeout.timeout(TIMEOUT):
        frame = await echo_client.get_message()
    assert frame.msg_type == picows.WSMsgType.TEXT
    assert frame.payload_as_ascii_text == msg.decode("ascii")
    assert frame.payload_as_utf8_text == msg.decode("utf8")
    assert frame.fin
    assert frame.rsv1

    # Check send defaults
    echo_client.transport.send(picows.WSMsgType.BINARY, msg)
    async with async_timeout.timeout(TIMEOUT):
        frame = await echo_client.get_message()
    assert frame.fin
    assert not frame.rsv1


async def test_close(echo_client):
    echo_client.transport.send_close(picows.WSCloseCode.GOING_AWAY, b"goodbye")
    async with async_timeout.timeout(TIMEOUT):
        frame = await echo_client.get_message()
    assert frame.msg_type == picows.WSMsgType.CLOSE
    assert frame.close_code == picows.WSCloseCode.GOING_AWAY
    assert frame.close_message == b"goodbye"


async def test_client_handshake_timeout(echo_server):
    # Set unreasonably small timeout
    with pytest.raises(TimeoutError):
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


async def test_route_not_found():
    server = await picows.ws_create_server(lambda _: None, "127.0.0.1", 0)
    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/"

        with pytest.raises(picows.WSError, match="404 Not Found"):
            (_, client) = await picows.ws_connect(picows.WSListener, url)


async def test_server_internal_error():
    def factory_listener(r):
        raise RuntimeError("oops")

    server = await picows.ws_create_server(factory_listener, "127.0.0.1", 0)
    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/"

        with pytest.raises(picows.WSError, match="500 Internal Server Error"):
            (_, client) = await picows.ws_connect(picows.WSListener, url)


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


async def test_ws_on_connected_throw():
    class ServerClientListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            raise RuntimeError("exception from on_ws_connected")


    server = await picows.ws_create_server(lambda _: ServerClientListener(),
                                           "127.0.0.1", 0)
    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        (transport, _) = await picows.ws_connect(picows.WSListener, url)
        async with async_timeout.timeout(TIMEOUT):
            await transport.wait_disconnected()


@pytest.mark.parametrize("disconnect_on_exception", [True, False])
async def test_ws_on_frame_throw(disconnect_on_exception):
    class ServerClientListener(picows.WSListener):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            raise RuntimeError("exception from on_ws_frame")

    server = await picows.ws_create_server(lambda _: ServerClientListener(),
                                           "127.0.0.1",
                                           0,
                                           disconnect_on_exception=disconnect_on_exception)

    async with ServerAsyncContext(server):
        url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/"

        (transport, _) = await picows.ws_connect(picows.WSListener, url)
        transport.send(picows.WSMsgType.BINARY, b"halo")
        try:
            if disconnect_on_exception:
                async with async_timeout.timeout(TIMEOUT):
                    await transport.wait_disconnected()
            else:
                with pytest.raises(TimeoutError):
                    async with async_timeout.timeout(TIMEOUT):
                        await transport.wait_disconnected()
        finally:
            transport.disconnect()
