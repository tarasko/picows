from __future__ import annotations

import asyncio
import binascii
import hmac
import http
import socket
import sys
from base64 import b64decode
from dataclasses import dataclass
from collections.abc import Awaitable, Callable, Iterable
from inspect import isawaitable
from logging import getLogger
from typing import Any, Optional, Pattern, Sequence, cast

import picows
from multidict import CIMultiDict

from .connection import (
    ServerConnection,
    broadcast_message,
)
from .negotiation import configure_permessage_deflate
from .utils import default_server_header, normalize_max_size, resolve_logger
from ..compat import Request, Response, State
from ..exceptions import ConcurrencyError, InvalidHandshake, InvalidOrigin
from ..typing import DataLike, LoggerLike, LoggerProtocol, MaxSize, Origin, Subprotocol

if sys.version_info >= (3, 11):
    from builtins import ExceptionGroup
else:
    ExceptionGroup = Exception

__all__ = [
    "ServerConnection",
    "ServerHandshakeConnection",
    "Server",
    "serve",
    "broadcast",
    "basic_auth",
]


_PERMESSAGE_DEFLATE_REQUEST = "permessage-deflate"


def _supports_permessage_deflate(request: Request) -> bool:
    value = request.headers.get("Sec-WebSocket-Extensions")
    return isinstance(value, str) and "permessage-deflate" in value


def _origin_allowed(
    origin: str | None,
    origins: Sequence[Origin | Pattern[str] | None] | None,
) -> bool:
    if origins is None:
        return True
    for candidate in origins:
        if candidate is None:
            if origin is None:
                return True
        elif isinstance(candidate, str):
            if origin == candidate:
                return True
        elif candidate.fullmatch(origin or "") is not None:
            return True
    return False


def _ensure_sync_result(value: Any, hook_name: str) -> Any:
    if isawaitable(value):
        close = getattr(value, "close", None)
        if close is not None:
            close()
        raise NotImplementedError(f"async {hook_name} hooks aren't supported by picows.websockets server yet")
    return value


def _make_error_response(
    status: http.HTTPStatus,
    body: bytes,
) -> Response:
    return Response(
        status_code=int(status),
        reason_phrase=status.phrase,
        headers=CIMultiDict({"Content-Type": "text/plain; charset=utf-8"}),
        body=body,
    )


def _basic_auth_unauthorized_response(message: bytes, realm: str) -> Response:
    response = _make_error_response(http.HTTPStatus.UNAUTHORIZED, message)
    response.headers["WWW-Authenticate"] = f'Basic realm="{realm}"'
    return response


def _parse_basic_authorization(header_value: str) -> tuple[str, str]:
    scheme, _, token = header_value.partition(" ")
    if scheme.lower() != "basic" or not token:
        raise ValueError("unsupported authorization scheme")
    try:
        decoded = b64decode(token, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ValueError("invalid basic authorization header") from exc
    username, separator, password = decoded.partition(":")
    if not separator:
        raise ValueError("invalid basic authorization header")
    return username, password


def _select_subprotocol(
    connection: ServerHandshakeConnection,
    request: Request,
    subprotocols: Optional[Sequence[Subprotocol]],
    select_subprotocol: Optional[Callable[[ServerHandshakeConnection, Sequence[Subprotocol]], Subprotocol | None]],
) -> Optional[Subprotocol]:
    header_value = request.headers.get("Sec-WebSocket-Protocol")
    if header_value is None:
        return None
    offered = [item.strip() for item in header_value.split(",") if item.strip()]
    if not offered:
        return None
    if select_subprotocol is not None:
        selected = select_subprotocol(connection, offered)
        if selected is not None and selected not in offered:
            raise InvalidHandshake(f"selected subprotocol isn't offered by client: {selected}")
        return selected
    if subprotocols is None:
        return None
    for subprotocol in subprotocols:
        if subprotocol in offered:
            return subprotocol
    return None


def _resolve_response_subprotocol(
    request: Request,
    response: Response,
) -> Optional[Subprotocol]:
    value = response.headers.get("Sec-WebSocket-Protocol")
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidHandshake("invalid Sec-WebSocket-Protocol header")
    header_value = request.headers.get("Sec-WebSocket-Protocol")
    if header_value is None:
        raise InvalidHandshake("server negotiated a subprotocol without a client offer")
    offered = [item.strip() for item in header_value.split(",") if item.strip()]
    if value not in offered:
        raise InvalidHandshake(f"selected subprotocol isn't offered by client: {value}")
    return value


def basic_auth(
    realm: str = "",
    credentials: tuple[str, str] | Iterable[tuple[str, str]] | None = None,
    check_credentials: Callable[[str, str], bool] | None = None,
) -> Callable[[ServerHandshakeConnection, Request], Response | None]:
    if (credentials is None) == (check_credentials is None):
        raise ValueError("provide either credentials or check_credentials")

    if credentials is not None:
        if (
            isinstance(credentials, tuple)
            and len(credentials) == 2
            and all(isinstance(item, str) for item in credentials)
        ):
            username = credentials[0]
            password = credentials[1]
            assert isinstance(username, str)
            assert isinstance(password, str)
            credentials_dict: dict[str, str] = {username: password}
        elif isinstance(credentials, Iterable):
            credentials_list: list[tuple[str, str]] = []
            for item in credentials:
                if (
                    not isinstance(item, tuple)
                    or len(item) != 2
                    or not isinstance(item[0], str)
                    or not isinstance(item[1], str)
                ):
                    raise TypeError(f"invalid credentials argument: {credentials}")
                credentials_list.append(item)
            credentials_dict = dict(credentials_list)
        else:
            raise TypeError(f"invalid credentials argument: {credentials}")

        def check_credentials(username: str, password: str) -> bool:
            expected_password: str | None = credentials_dict.get(username)
            return (
                expected_password is not None
                and hmac.compare_digest(expected_password, password)
            )

    assert check_credentials is not None

    def process_request(
        connection: ServerHandshakeConnection,
        request: Request,
    ) -> Response | None:
        authorization = request.headers.get("Authorization")
        if authorization is None:
            return _basic_auth_unauthorized_response(b"Missing credentials\n", realm)

        try:
            username, password = _parse_basic_authorization(authorization)
        except ValueError:
            return _basic_auth_unauthorized_response(b"Unsupported credentials\n", realm)

        valid_credentials = check_credentials(username, password)
        if isawaitable(valid_credentials):
            close = getattr(valid_credentials, "close", None)
            if close is not None:
                close()
            raise NotImplementedError("async basic_auth credential checks aren't supported yet")
        if not valid_credentials:
            return _basic_auth_unauthorized_response(b"Invalid credentials\n", realm)

        connection.username = username
        return None

    return process_request


@dataclass
class ServerHandshakeConnection:
    request: Request
    username: Optional[str] = None

    @property
    def state(self) -> State:
        return State.CONNECTING


class Server:
    def __init__(
        self,
        handler: Callable[[ServerConnection], Awaitable[None]],
        *,
        logger: LoggerProtocol,
    ) -> None:
        self.loop = asyncio.get_running_loop()
        self.handler = handler
        self.logger = logger
        self.handlers: dict[ServerConnection, asyncio.Task[None]] = {}
        self.close_task: asyncio.Task[None] | None = None
        self.closed_waiter: asyncio.Future[None] = self.loop.create_future()
        self.server: asyncio.Server

    @property
    def connections(self) -> set[ServerConnection]:
        return {connection for connection in self.handlers if connection.state is State.OPEN}

    def wrap(self, server: asyncio.Server) -> None:
        self.server = server
        for sock in server.sockets:
            if sock.family == socket.AF_INET:
                name = "%s:%d" % sock.getsockname()
            elif sock.family == socket.AF_INET6:
                name = "[%s]:%d" % sock.getsockname()[:2]
            else:
                name = str(sock.getsockname())
            self.logger.info("server listening on %s", name)

    async def conn_handler(self, connection: ServerConnection) -> None:
        try:
            try:
                await asyncio.sleep(0)
                await self.handler(connection)
            except Exception:
                self.logger.error("connection handler failed", exc_info=True)
                await connection.close(1011)
            else:
                await connection.close()
        finally:
            del self.handlers[connection]

    def start_connection_handler(self, connection: ServerConnection) -> None:
        self.handlers[connection] = self.loop.create_task(self.conn_handler(connection))

    def close(
        self,
        close_connections: bool = True,
        code: int = 1001,
        reason: str = "",
    ) -> None:
        if self.close_task is None:
            self.close_task = self.loop.create_task(self._close(close_connections, code, reason))

    async def _close(
        self,
        close_connections: bool = True,
        code: int = 1001,
        reason: str = "",
    ) -> None:
        self.logger.info("server closing")
        self.server.close()
        await asyncio.sleep(0)
        if close_connections:
            close_tasks = [
                asyncio.create_task(connection.close(code, reason))
                for connection in self.handlers
                if connection.state is not State.CONNECTING
            ]
            if close_tasks:
                await asyncio.wait(close_tasks)
        await self.server.wait_closed()
        if self.handlers:
            await asyncio.wait(self.handlers.values())
        self.closed_waiter.set_result(None)
        self.logger.info("server closed")

    async def wait_closed(self) -> None:
        await asyncio.shield(self.closed_waiter)

    def get_loop(self) -> asyncio.AbstractEventLoop:
        return self.server.get_loop()

    def is_serving(self) -> bool:
        return self.server.is_serving()

    async def start_serving(self) -> None:
        await self.server.start_serving()

    async def serve_forever(self) -> None:
        await self.server.serve_forever()

    @property
    def sockets(self) -> tuple[socket.socket, ...]:
        return self.server.sockets

    async def __aenter__(self) -> Server:
        return self

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()
        await self.wait_closed()


class serve:
    def __init__(
        self,
        handler: Callable[[ServerConnection], Awaitable[None]],
        host: str | None = None,
        port: int | None = None,
        *,
        origins: Sequence[Origin | Pattern[str] | None] | None = None,
        extensions: Sequence[Any] | None = None,
        subprotocols: Sequence[Subprotocol] | None = None,
        select_subprotocol: Callable[[ServerHandshakeConnection, Sequence[Subprotocol]], Subprotocol | None] | None = None,
        compression: str | None = "deflate",
        server_header: str | None = default_server_header(),
        open_timeout: float | None = 10,
        ping_interval: float | None = 20,
        ping_timeout: float | None = 20,
        close_timeout: float | None = 10,
        max_size: MaxSize = 1024 * 1024,
        max_queue: int | None | tuple[int | None, int | None] = 16,
        write_limit: int | tuple[int, int | None] = 32768,
        logger: LoggerLike | None = None,
        **kwargs: Any,
    ):
        self.handler = handler
        self.host = host
        self.port = port
        self.origins = origins
        self.extensions = extensions
        self.subprotocols = subprotocols
        self.select_subprotocol = select_subprotocol
        self.compression = compression
        self.server_header = server_header
        self.open_timeout = open_timeout
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.close_timeout = close_timeout
        self.max_size = max_size
        self.max_queue = max_queue
        self.write_limit = write_limit
        self.logger = logger
        if "create_connection" in kwargs:
            raise NotImplementedError("create_connection isn't supported by picows.websockets server yet")
        self.process_request = kwargs.pop("process_request", None)
        self.process_response = kwargs.pop("process_response", None)
        self.kwargs = kwargs
        self._server: Server | None = None

    def __await__(self) -> Any:
        return self._create().__await__()

    async def __aenter__(self) -> Server:
        self._server = await self._create()
        return self._server

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _create(self) -> Server:
        if self.extensions is not None:
            raise NotImplementedError("custom server extensions aren't supported by picows.websockets")
        if self.compression not in (None, "deflate"):
            raise NotImplementedError("only compression=None or 'deflate' are accepted")

        logger = resolve_logger(self.logger, "websockets.server")

        server = Server(
            self.handler,
            logger=logger,
        )

        max_message_size, max_frame_size = normalize_max_size(self.max_size)

        def listener_factory(
            upgrade_request: picows.WSUpgradeRequest,
        ) -> picows.WSUpgradeResponseWithListener:
            request = Request.from_picows(upgrade_request)
            handshake_connection = ServerHandshakeConnection(request)
            response: Response

            origin = request.headers.get("Origin")
            if origin is not None and not isinstance(origin, str):
                raise InvalidOrigin(None)
            if not _origin_allowed(origin, self.origins):
                response = _make_error_response(
                    http.HTTPStatus.FORBIDDEN,
                    b"Origin not allowed\n",
                )
            elif server.close_task is not None:
                response = _make_error_response(
                    http.HTTPStatus.SERVICE_UNAVAILABLE,
                    b"Server is shutting down.\n",
                )
            else:
                headers = {}
                if self.server_header is not None:
                    headers["Server"] = self.server_header
                subprotocol = _select_subprotocol(
                    handshake_connection,
                    request,
                    self.subprotocols,
                    self.select_subprotocol,
                )
                if subprotocol is not None:
                    headers["Sec-WebSocket-Protocol"] = subprotocol
                if self.compression == "deflate" and _supports_permessage_deflate(request):
                    headers["Sec-WebSocket-Extensions"] = _PERMESSAGE_DEFLATE_REQUEST
                response = Response.from_picows(picows.WSUpgradeResponse.create_101_response(headers))

            if self.process_request is not None:
                response_or_none = _ensure_sync_result(
                    self.process_request(handshake_connection, request),
                    "process_request",
                )
                if response_or_none is not None:
                    if not isinstance(response_or_none, Response):
                        raise TypeError("process_request must return a Response or None")
                    response = response_or_none

            response = _ensure_sync_result(
                self.process_response(handshake_connection, request, response),
                "process_response",
            ) if self.process_response is not None else response

            if not isinstance(response, Response):
                raise TypeError("process_response must return a Response")

            if response.status_code == int(http.HTTPStatus.SWITCHING_PROTOCOLS):
                subprotocol = _resolve_response_subprotocol(request, response)
                permessage_deflate = configure_permessage_deflate(response, self.compression)
                connection = ServerConnection(
                    server,
                    request=request,
                    response=response,
                    subprotocol=subprotocol,
                    permessage_deflate=permessage_deflate,
                    username=handshake_connection.username,
                    ping_interval=self.ping_interval,
                    ping_timeout=self.ping_timeout,
                    close_timeout=self.close_timeout,
                    max_queue=self.max_queue,
                    write_limit=self.write_limit,
                    max_message_size=max_message_size,
                    max_frame_size=max_frame_size,
                    logger=logger,
                )
                return picows.WSUpgradeResponseWithListener(response.to_picows(), connection)
            else:
                return picows.WSUpgradeResponseWithListener(response.to_picows(), None)

        raw_server = await picows.ws_create_server(
            listener_factory,
            self.host,
            self.port,
            websocket_handshake_timeout=self.open_timeout,
            enable_auto_ping=False,
            enable_auto_pong=True,
            max_frame_size=max_frame_size,
            logger_name=cast(Any, logger),
            **self.kwargs,
        )
        server.wrap(raw_server)
        return server


def broadcast(
    connections: Iterable[ServerConnection],
    message: DataLike,
    raise_exceptions: bool = False,
) -> None:
    if isinstance(message, str):
        msg_type = picows.WSMsgType.TEXT
    elif isinstance(message, (bytes, bytearray, memoryview)):
        msg_type = picows.WSMsgType.BINARY
    else:
        raise TypeError("data must be str or bytes")

    if raise_exceptions:
        if sys.version_info[:2] < (3, 11):
            raise ValueError("raise_exceptions requires at least Python 3.11")
        exceptions: list[Exception] = []

    for connection in connections:
        if connection.state is not State.OPEN:
            continue
        try:
            sent = broadcast_message(connection, msg_type, message)
        except Exception as write_exception:
            if raise_exceptions:
                exception = RuntimeError("failed to write message")
                exception.__cause__ = write_exception
                exceptions.append(exception)
            else:
                getLogger("websockets.server").warning(
                    "skipped broadcast: failed to write message: %s",
                    write_exception,
                )
            continue

        if not sent:
            if raise_exceptions:
                exceptions.append(ConcurrencyError("sending a fragmented message"))
            else:
                getLogger("websockets.server").warning("skipped broadcast: sending a fragmented message")

    if raise_exceptions and exceptions:
        raise ExceptionGroup("skipped broadcast", exceptions)
