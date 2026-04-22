import asyncio
import base64
import os

import picows
import pytest
import async_timeout

from http import HTTPStatus
from tests.utils import (TIMEOUT, AsyncClient, WSServer, WSClient, TestException)
from tests.fixtures import multiloop_event_loop_policy

event_loop_policy = multiloop_event_loop_policy()


@pytest.mark.parametrize("msg_size", [0, 1, 2, 3, 4, 5, 6, 7, 8, 29, 64, 256 * 1024, 6*1024*1024])
async def test_echo(use_aiofastnet, ssl_context, msg_size):
    async with WSServer(ssl=ssl_context.server, use_aiofastnet=use_aiofastnet) as server:
        async with WSClient(server, ssl_context=ssl_context.client, use_aiofastnet=use_aiofastnet) as client:
            msg = (b"ABCDEFGHIKLMNOPQ" * (int(msg_size / 16) + 1))[:msg_size]

            client.transport.send(picows.WSMsgType.BINARY, msg, False, False)
            frame = await client.get_message()
            assert frame.frame_str.startswith("WSFrame(BINARY, fin=False, rsv1=False")
            assert frame.msg_type == picows.WSMsgType.BINARY
            assert frame.payload_as_bytes == msg
            assert frame.payload_as_bytes_from_mv == msg
            assert not frame.fin
            assert not frame.rsv1

            ba = bytearray(b"1234567890123456")
            ba += msg
            client.transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, ba, 16)
            frame = await client.get_message()
            assert frame.frame_str.startswith("WSFrame(BINARY, fin=True, rsv1=False")
            assert frame.msg_type == picows.WSMsgType.BINARY
            assert frame.payload_as_bytes == msg

            msg = base64.b64encode(msg)
            client.transport.send(picows.WSMsgType.TEXT, msg, True, True)
            frame = await client.get_message()
            assert frame.frame_str.startswith("WSFrame(TEXT, fin=True, rsv1=True")
            assert frame.msg_type == picows.WSMsgType.TEXT
            assert frame.payload_as_ascii_text == msg.decode("ascii")
            assert frame.payload_as_utf8_text == msg.decode("utf8")
            assert frame.fin
            assert frame.rsv1

            # Check send defaults
            client.transport.send(picows.WSMsgType.BINARY, msg)
            frame = await client.get_message()
            assert frame.fin
            assert not frame.rsv1

            # Test non-bytes like send
            with pytest.raises(TypeError):
                client.transport.send(picows.WSMsgType.BINARY, "hi")


async def test_echo_control_frames(use_aiofastnet, ssl_context):
    async with WSServer(ssl=ssl_context.server, use_aiofastnet=use_aiofastnet) as server:
        async with WSClient(server, ssl_context=ssl_context.client, use_aiofastnet=use_aiofastnet) as client:
            # Check ping
            client.transport.send_ping(b"hi")
            frame = await client.get_message()
            assert frame.frame_str.startswith("WSFrame(PING, fin=True, rsv1=False")
            assert frame.msg_type == picows.WSMsgType.PING
            assert frame.payload_as_bytes == b"hi"

            # Check pong
            client.transport.send_pong(b"hi")
            frame = await client.get_message()
            assert frame.frame_str.startswith("WSFrame(PONG, fin=True, rsv1=False")
            assert frame.msg_type == picows.WSMsgType.PONG
            assert frame.payload_as_bytes == b"hi"

            # Check close
            client.transport.send_close(picows.WSCloseCode.GOING_AWAY, b"goodbye")
            assert client.transport.is_close_frame_sent
            frame = await client.get_message()
            assert frame.frame_str.startswith("WSFrame(CLOSE, fin=True, rsv1=False")
            assert frame.msg_type == picows.WSMsgType.CLOSE
            assert frame.close_code == picows.WSCloseCode.GOING_AWAY
            assert frame.close_message == b"goodbye"



async def test_client_handshake_timeout(use_aiofastnet, ssl_context):
    async with WSServer(ssl=ssl_context.server, use_aiofastnet=use_aiofastnet) as server:
        # Set unreasonably small timeout
        with pytest.raises(asyncio.TimeoutError):
            async with WSClient(server,
                                ssl_context=ssl_context.client,
                                use_aiofastnet=use_aiofastnet,
                                websocket_handshake_timeout=0.00001) as client:
                pass


async def test_server_handshake_timeout(use_aiofastnet):
    async with WSServer(use_aiofastnet=use_aiofastnet, websocket_handshake_timeout=0.1) as server:
        # Give some time for server to start
        await asyncio.sleep(0.1)

        client_reader, client_writer = await asyncio.open_connection(server.host, server.port)
        assert not client_reader.at_eof()
        await asyncio.sleep(0.2)
        assert client_reader.at_eof()


async def test_client_multiple_disconnect(use_aiofastnet, ssl_context):
    async with WSServer(ssl=ssl_context.server, use_aiofastnet=use_aiofastnet) as server:
        async with WSClient(server, ssl_context=ssl_context.client, use_aiofastnet=use_aiofastnet) as client:
            client.transport.disconnect()
            client.transport.disconnect()
            client.transport.disconnect()

            await client.transport.wait_disconnected()

        async with WSClient(server, ssl_context=ssl_context.client, use_aiofastnet=use_aiofastnet) as client:
            client.transport.disconnect(False)
            client.transport.disconnect(False)
            client.transport.disconnect(False)

            await client.transport.wait_disconnected()


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

    async with WSServer(listener_factory) as server:
        async with WSClient(server, extra_headers=extra_headers) as client:
            assert request_from_client.headers["User-Agent"] == "picows"
            assert request_from_client.headers["token"] == "abc"
            assert client.transport.request.headers["User-Agent"] == "picows"
            assert client.transport.request.headers["token"] == "abc"


async def test_ws_on_connected_raise_client_side(use_aiofastnet, ssl_context):
    # Check that client side, initiate disconnect(no timeouts on wait_disconnected) and
    # transfer exception to wait_disconnected
    class ClientListener(AsyncClient):
        def on_ws_connected(self, transport: picows.WSTransport):
            super().on_ws_connected(transport)
            raise TestException("exception from client side on_ws_connected")

    async with WSServer(use_aiofastnet=use_aiofastnet, ssl=ssl_context.server) as server:
        with pytest.raises(TestException):
            async with WSClient(server, ClientListener, use_aiofastnet=use_aiofastnet, ssl_context=ssl_context.client) as client:
                async with async_timeout.timeout(TIMEOUT):
                    await client.transport.wait_disconnected()


async def test_ws_on_connected_raise_server_side(use_aiofastnet, ssl_context):
    # Check that server side initiate disconnect(no timeouts on wait_disconnected) and
    # swallow exception
    class ServerClientListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            raise TestException("exception from server side on_ws_connected")

    async with WSServer(lambda _: ServerClientListener(), use_aiofastnet=use_aiofastnet, ssl=ssl_context.server) as server:
        async with WSClient(server, use_aiofastnet=use_aiofastnet, ssl_context=ssl_context.client) as client:
            async with async_timeout.timeout(TIMEOUT):
                await client.transport.wait_disconnected()


@pytest.mark.parametrize("disconnect_on_exception", [True, False],
                         ids=["disconnect_on_exception", "no_disconnect_on_exception"])
async def test_ws_on_frame_raise_client_side(use_aiofastnet, ssl_context, disconnect_on_exception):
    class ServerClientListener(picows.WSListener):
        def on_ws_connected(self, transport: picows.WSTransport):
            transport.send(picows.WSMsgType.BINARY, b"Hello")

    class ClientListener(AsyncClient):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            raise TestException("exception from client side on_ws_frame")

    async with WSServer(lambda _: ServerClientListener(),
                        use_aiofastnet=use_aiofastnet, ssl=ssl_context.server) as server:
        async with WSClient(server, ClientListener,
                            use_aiofastnet=use_aiofastnet, ssl_context=ssl_context.client,
                            disconnect_on_exception=disconnect_on_exception) as client:
            if disconnect_on_exception:
                with pytest.raises(TestException):
                    async with async_timeout.timeout(TIMEOUT):
                        await client.transport.wait_disconnected()
            else:
                with pytest.raises(asyncio.TimeoutError):
                    async with async_timeout.timeout(TIMEOUT):
                        await client.transport.wait_disconnected()


@pytest.mark.parametrize("disconnect_on_exception", [True, False],
                         ids=["disconnect_on_exception", "no_disconnect_on_exception"])
async def test_ws_on_frame_raise_server_side(use_aiofastnet, ssl_context, disconnect_on_exception):
    class ServerClientListener(picows.WSListener):
        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            raise TestException("exception from server side on_ws_frame")

    async with WSServer(lambda _: ServerClientListener(),
                        use_aiofastnet=use_aiofastnet, ssl=ssl_context.server,
                        disconnect_on_exception=disconnect_on_exception) as server:
        async with WSClient(server,
                            use_aiofastnet=use_aiofastnet, ssl_context=ssl_context.client) as client:
            client.transport.send(picows.WSMsgType.BINARY, b"halo")

            if disconnect_on_exception:
                async with async_timeout.timeout(TIMEOUT):
                    await client.transport.wait_disconnected()
            else:
                with pytest.raises(asyncio.TimeoutError):
                    async with async_timeout.timeout(TIMEOUT):
                        await client.transport.wait_disconnected()


async def test_ws_on_disconnected_raise_client_side(use_aiofastnet, ssl_context):
    # Check that exception is transferred to wait_disconnected from on_ws_disconnected
    class ClientListener(AsyncClient):
        def on_ws_disconnected(self, transport):
            raise TestException("exception from on_ws_disconnected")

    async with WSServer(use_aiofastnet=use_aiofastnet, ssl=ssl_context.server) as server:
        async with WSClient(server, ClientListener,
                            use_aiofastnet=use_aiofastnet, ssl_context=ssl_context.client) as client:
            async with async_timeout.timeout(TIMEOUT):
                with pytest.raises(TestException):
                    client.transport.disconnect()
                    await client.transport.wait_disconnected()


async def test_stress(use_aiofastnet, ssl_context):
    # Heuristic check if picows direct write works smoothly together with
    # loop transport write. We have to fill socket system buffers first
    # and then loop Transport.write kicks in. Only after that we get pause_writing

    async with WSServer(use_aiofastnet=use_aiofastnet, ssl=ssl_context.server) as server:
        async with WSClient(server,
                            use_aiofastnet=use_aiofastnet, ssl_context=ssl_context.client) as client:
            client.transport.underlying_transport.set_write_buffer_limits(256, 128)

            msg1 = os.urandom(307)
            msg2 = os.urandom(311)
            msg3 = os.urandom(313)

            total_batches = 0
            while not client.is_paused:
                client.transport.send(picows.WSMsgType.BINARY, msg1)
                client.transport.send(picows.WSMsgType.BINARY, msg2)
                client.transport.send(picows.WSMsgType.BINARY, msg3)
                total_batches += 1

            # Add extra batch to make sure we utilize loop buffers above high watermark
            client.transport.send(picows.WSMsgType.BINARY, msg1)
            client.transport.send(picows.WSMsgType.BINARY, msg2)
            client.transport.send(picows.WSMsgType.BINARY, msg3)
            total_batches += 1

            for i in range(total_batches * 3):
                async with async_timeout.timeout(TIMEOUT*2):
                    frame = await client.get_message()

                if i % 3 == 0:
                    assert frame.payload_as_bytes == msg1
                elif i % 3 == 1:
                    assert frame.payload_as_bytes == msg2
                else:
                    assert frame.payload_as_bytes == msg3

            with pytest.raises(asyncio.TimeoutError):
                async with async_timeout.timeout(TIMEOUT):
                    frame = await client.get_message()

            assert not client.is_paused

#