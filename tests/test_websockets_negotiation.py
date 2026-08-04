import asyncio
import base64
import hashlib
from contextlib import asynccontextmanager
from typing import Optional

import picows
import pytest
import websockets as upstream_websockets
from multidict import CIMultiDict

from picows.picows import _make_test_ws_frame
from picows import websockets
from picows.websockets.asyncio.connection import _PerMessageDeflate
from picows.websockets.asyncio.negotiation import configure_permessage_deflate, resolve_subprotocol
from tests.utils import WSServer


@asynccontextmanager
async def upstream_server(handler):
    server = await upstream_websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression="deflate",
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"ws://127.0.0.1:{port}/"
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def malformed_compressed_server():
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        request = await reader.readuntil(b"\r\n\r\n")
        headers = request.decode("ascii").split("\r\n")
        key = None
        for header in headers:
            if header.lower().startswith("sec-websocket-key:"):
                key = header.split(":", 1)[1].strip()
                break
        assert key is not None

        accept = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()
        ).decode("ascii")

        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "Sec-WebSocket-Extensions: permessage-deflate\r\n"
            "\r\n"
        )
        writer.write(response.encode("ascii"))

        payload = b"not-a-valid-deflate-stream"
        frame = bytes([0xC1, len(payload)]) + payload
        writer.write(frame)
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"ws://127.0.0.1:{port}/"
    finally:
        server.close()
        await server.wait_closed()


async def test_subprotocol_header_and_property():
    request_headers = {}

    def listener_factory(request):
        request_headers["value"] = request.headers.get("Sec-WebSocket-Protocol")
        return None

    async with WSServer(listener_factory) as server:
        with pytest.raises(websockets.InvalidStatus):
            async with websockets.connect(server.url, compression=None, subprotocols=["chat"]):
                pass

        assert request_headers["value"] == "chat"


async def test_serve_negotiates_subprotocol():
    async def handler(ws: websockets.ServerConnection) -> None:
        await ws.wait_closed()

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        subprotocols=["chat", "superchat"],
    ) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(
            f"ws://127.0.0.1:{port}/",
            compression=None,
            subprotocols=["superchat", "chat"],
        ) as ws:
            assert ws.subprotocol == "chat"


async def test_select_subprotocol_receives_handshake_connection():
    seen = {}

    async def handler(ws: websockets.ServerConnection) -> None:
        await ws.wait_closed()

    def select_subprotocol(
        ws: websockets.ServerHandshakeConnection,
        offered: list[str],
    ) -> Optional[str]:
        seen["type"] = type(ws)
        seen["path"] = ws.request.path
        seen["state"] = ws.state
        seen["has_recv"] = hasattr(ws, "recv")
        if "chat" in offered:
            return "chat"
        return None

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        select_subprotocol=select_subprotocol,
    ) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(
            f"ws://127.0.0.1:{port}/room",
            compression=None,
            subprotocols=["chat"],
        ) as ws:
            assert ws.subprotocol == "chat"

    assert seen["type"] is websockets.ServerHandshakeConnection
    assert seen["path"] == "/room"
    assert seen["state"] is websockets.State.CONNECTING
    assert seen["has_recv"] is False


def test_negotiation_rejects_invalid_subprotocol_and_extension_headers():
    response = websockets.Response(101, "Switching Protocols", CIMultiDict(), b"")

    response.headers["Sec-WebSocket-Protocol"] = 123  # type: ignore[assignment]
    with pytest.raises(websockets.InvalidHandshake, match="non-string subprotocol"):
        resolve_subprotocol(["chat"], response)

    response.headers["Sec-WebSocket-Protocol"] = "other"
    with pytest.raises(websockets.InvalidHandshake, match="unsupported subprotocol"):
        resolve_subprotocol(["chat"], response)

    response.headers.clear()
    response.headers["Sec-WebSocket-Extensions"] = "permessage-deflate"
    with pytest.raises(websockets.InvalidHandshake, match="unexpected websocket extensions"):
        configure_permessage_deflate(response, None)

    response.headers["Sec-WebSocket-Extensions"] = 123  # type: ignore[assignment]
    with pytest.raises(websockets.InvalidHandshake, match="invalid Sec-WebSocket-Extensions"):
        configure_permessage_deflate(response, "deflate")


def test_permessage_deflate_rejects_invalid_parameters():
    response = websockets.Response(101, "Switching Protocols", CIMultiDict(), b"")
    invalid_headers = [
        "x-webkit-deflate-frame",
        "permessage-deflate, permessage-deflate",
        "permessage-deflate; server_no_context_takeover=true",
        "permessage-deflate; client_no_context_takeover=true",
        "permessage-deflate; server_max_window_bits",
        "permessage-deflate; server_max_window_bits=7",
        "permessage-deflate; client_max_window_bits",
        "permessage-deflate; client_max_window_bits=16",
        "permessage-deflate; unknown=value",
        "permessage-deflate; server_max_window_bits=15; server_max_window_bits=15",
    ]

    for header in invalid_headers:
        response.headers["Sec-WebSocket-Extensions"] = header
        with pytest.raises(websockets.InvalidHandshake):
            configure_permessage_deflate(response, "deflate")


def test_permessage_deflate_accepts_no_context_takeover_parameters():
    permessage_deflate = _PerMessageDeflate.from_response_header(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
    )

    first = permessage_deflate.encode_frame(picows.WSMsgType.TEXT, "hello", True)
    second = permessage_deflate.encode_frame(picows.WSMsgType.TEXT, b"hello", True)

    assert isinstance(first, memoryview)
    assert isinstance(second, memoryview)
    assert bytes(first)
    assert bytes(second)


def test_permessage_deflate_decode_passthrough_and_protocol_error_branches():
    permessage_deflate = _PerMessageDeflate.from_response_header(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
    )

    assert permessage_deflate.decode_frame(
        _make_test_ws_frame(picows.WSMsgType.TEXT, b"plain", fin=False, rsv1=False),
        0,
    ) == b"plain"
    assert permessage_deflate.decode_frame(
        _make_test_ws_frame(picows.WSMsgType.CONTINUATION, b"continuation", fin=True, rsv1=False),
        0,
    ) == b"continuation"

    encoded = bytes(permessage_deflate.encode_frame(picows.WSMsgType.TEXT, b"compressed", True))
    assert permessage_deflate.decode_frame(
        _make_test_ws_frame(picows.WSMsgType.TEXT, encoded, fin=False, rsv1=True),
        100,
    ) == b"compressed"

    with pytest.raises(picows.WSProtocolError, match="unexpected rsv1"):
        permessage_deflate.decode_frame(
            _make_test_ws_frame(picows.WSMsgType.CONTINUATION, b"bad", fin=True, rsv1=True),
            0,
        )


async def test_permessage_deflate_echo_with_upstream_server():
    async def handler(ws):
        async for message in ws:
            await ws.send(message)

    async with upstream_server(handler) as url:
        async with websockets.connect(url, ping_interval=None) as ws:
            assert "permessage-deflate" in (ws.response.headers.get("Sec-WebSocket-Extensions") or "")

            message = "hello " * 1000
            await ws.send(message)
            assert await ws.recv() == message


async def test_permessage_deflate_fragmented_send_with_upstream_server():
    async def handler(ws):
        async for message in ws:
            await ws.send(message)

    async with upstream_server(handler) as url:
        async with websockets.connect(url, ping_interval=None) as ws:
            await ws.send([b"a" * 300, b"b" * 300, b"c" * 300])
            assert await ws.recv() == (b"a" * 300 + b"b" * 300 + b"c" * 300)


async def test_permessage_deflate_recv_streaming_from_upstream_server():
    chunks = [b"ab" * 300, b"cd" * 300, b"ef" * 300]

    async def handler(ws):
        await ws.send(chunks)
        await ws.close()

    async with upstream_server(handler) as url:
        async with websockets.connect(url, ping_interval=None) as ws:
            fragments = []
            async for fragment in ws.recv_streaming():
                fragments.append(fragment)
            assert fragments == chunks + [b""]


async def test_compressed_message_exceeding_max_size_closes_connection():
    async def handler(ws):
        await ws.send("a" * 10000)

    async with upstream_server(handler) as url:
        async with websockets.connect(
            url, ping_interval=None, max_size=1000
        ) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()


async def test_malformed_compressed_message_closes_connection():
    async with malformed_compressed_server() as url:
        async with websockets.connect(url, ping_interval=None) as ws:
            with pytest.raises(websockets.ConnectionClosedError):
                await ws.recv()
