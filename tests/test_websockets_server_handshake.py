import base64
import re
from typing import Optional

import pytest
from multidict import CIMultiDict

from picows import websockets
from picows.websockets.asyncio.server import _parse_basic_authorization


async def test_serve_process_request_can_reject_handshake():
    async def handler(ws: websockets.ServerConnection) -> None:
        raise AssertionError("handler must not be called")

    def process_request(
        ws: websockets.ServerHandshakeConnection,
        request: websockets.Request,
    ) -> Optional[websockets.Response]:
        assert ws.request is request
        return websockets.Response(
            status_code=418,
            reason_phrase="I'm a Teapot",
            headers=CIMultiDict({"X-Test": "yes"}),
            body=b"nope",
        )

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        process_request=process_request,
    ) as server:
        port = server.sockets[0].getsockname()[1]
        with pytest.raises(websockets.InvalidStatus) as exc_info:
            async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None):
                pass
        assert int(exc_info.value.response.status) == 418


async def test_serve_process_response_can_mutate_handshake_response():
    async def handler(ws: websockets.ServerConnection) -> None:
        await ws.wait_closed()

    def process_response(
        ws: websockets.ServerHandshakeConnection,
        request: websockets.Request,
        response: websockets.Response,
    ) -> websockets.Response:
        assert ws.request is request
        response.headers["X-Handshake"] = "yes"
        return response

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        process_response=process_response,
    ) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None) as ws:
            assert ws.response.headers["X-Handshake"] == "yes"


async def test_serve_rejects_async_process_request():
    async def handler(ws: websockets.ServerConnection) -> None:
        raise AssertionError("handler must not be called")

    async def process_request(
        ws: websockets.ServerHandshakeConnection,
        request: websockets.Request,
    ) -> Optional[websockets.Response]:
        return None

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        process_request=process_request,
    ) as server:
        port = server.sockets[0].getsockname()[1]
        with pytest.raises(websockets.InvalidStatus):
            async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None):
                pass


async def test_serve_accepts_allowed_origin():
    async def handler(ws: websockets.ServerConnection) -> None:
        await ws.send("ok")

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        origins=["https://example.com"],
    ) as server:
        port = server.sockets[0].getsockname()[1]
        async with websockets.connect(
            f"ws://127.0.0.1:{port}/",
            compression=None,
            origin="https://example.com",
        ) as ws:
            assert await ws.recv() == "ok"


async def test_serve_rejects_disallowed_origin():
    async def handler(ws: websockets.ServerConnection) -> None:
        raise AssertionError("handler must not be called")

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        origins=[re.compile(r"https://allowed\\.example\\.com")],
    ) as server:
        port = server.sockets[0].getsockname()[1]
        with pytest.raises(websockets.InvalidStatus):
            async with websockets.connect(
                f"ws://127.0.0.1:{port}/",
                compression=None,
                origin="https://denied.example.com",
            ):
                pass


async def test_basic_auth_rejects_missing_credentials_and_sets_username():
    async def handler(ws: websockets.ServerConnection) -> None:
        assert ws.username == "hello"
        await ws.send(ws.username)

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        process_request=websockets.basic_auth(
            realm="test",
            credentials=("hello", "secret"),
        ),
    ) as server:
        port = server.sockets[0].getsockname()[1]

        with pytest.raises(websockets.InvalidStatus) as exc_info:
            async with websockets.connect(f"ws://127.0.0.1:{port}/", compression=None):
                pass
        assert int(exc_info.value.response.status) == 401
        assert exc_info.value.response.headers["WWW-Authenticate"] == 'Basic realm="test"'

        token = base64.b64encode(b"hello:secret").decode()
        async with websockets.connect(
            f"ws://127.0.0.1:{port}/",
            compression=None,
            additional_headers={"Authorization": f"Basic {token}"},
        ) as ws:
            assert await ws.recv() == "hello"


def test_basic_auth_argument_validation_and_malformed_headers():
    with pytest.raises(ValueError, match="provide either credentials or check_credentials"):
        websockets.basic_auth()
    with pytest.raises(ValueError, match="provide either credentials or check_credentials"):
        websockets.basic_auth(credentials=("a", "b"), check_credentials=lambda _u, _p: True)
    with pytest.raises(TypeError, match="invalid credentials argument"):
        websockets.basic_auth(credentials=("a", "b", "c"))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="invalid credentials argument"):
        websockets.basic_auth(credentials=[("a", object())])  # type: ignore[list-item]

    with pytest.raises(ValueError, match="unsupported authorization scheme"):
        _parse_basic_authorization("Bearer token")
    with pytest.raises(ValueError, match="invalid basic authorization header"):
        _parse_basic_authorization("Basic !!!")
    with pytest.raises(ValueError, match="invalid basic authorization header"):
        _parse_basic_authorization("Basic bm9jb2xvbg==")


async def test_basic_auth_rejects_bad_and_async_credentials():
    async def handler(_ws: websockets.ServerConnection) -> None:
        raise AssertionError("handler must not be called")

    async def check_credentials(_username: str, _password: str) -> bool:
        return True

    async with websockets.serve(
        handler,
        "127.0.0.1",
        0,
        compression=None,
        process_request=websockets.basic_auth(check_credentials=check_credentials),
    ) as server:
        port = server.sockets[0].getsockname()[1]
        token = "Basic " + "aW52YWxpZDpjcmVkZW50aWFscw=="
        with pytest.raises(websockets.InvalidStatus):
            async with websockets.connect(
                f"ws://127.0.0.1:{port}/",
                compression=None,
                additional_headers={"Authorization": token},
            ):
                pass
