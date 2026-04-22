import asyncio
import os
from http import HTTPStatus

import async_timeout
import pytest

import picows
from tests.utils import WSServer, WSClient, TIMEOUT
from tests.fixtures import use_aiofastnet, ssl_context


async def test_send_external_bytearray_asserts():
    async with WSServer() as server:
        async with WSClient(server) as client:
            with pytest.raises(AssertionError):
                # Check assertion for msg_len >= 0
                client.transport.send_reuse_external_bytearray(picows.WSMsgType.BINARY, bytearray(b"HELLO"), 16)

            with pytest.raises(AssertionError):
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
        with pytest.raises(picows.WSError, match="violates max allowed size"):
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
