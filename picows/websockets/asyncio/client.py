from __future__ import annotations

import asyncio
import socket
from collections.abc import Generator
from ssl import SSLContext
from typing import Any, Callable, Optional, Sequence, Union

import picows
from picows.url import parse_url

from .connection import (
    ClientConnection,
    process_exception,
)
from .negotiation import configure_permessage_deflate, resolve_subprotocol
from .utils import default_user_agent, normalize_max_size, resolve_logger
from ..compat import Request, Response
from ..exceptions import (
    InvalidHandshake,
    InvalidHeader,
    InvalidMessage,
    InvalidProxy,
    InvalidStatus,
    InvalidUpgrade,
    InvalidURI,
)
from ..typing import HeadersLike, LoggerLike, MaxSize, Origin, Subprotocol

__all__ = [
    "ClientConnection",
    "connect",
]


_PERMESSAGE_DEFLATE_REQUEST = "permessage-deflate; client_max_window_bits"


def _header_items(headers: Any) -> list[tuple[str, str]]:
    return [] if headers is None else list(headers.items())


def _process_proxy(proxy: Union[str, bool, None], secure: bool) -> Optional[str]:
    from urllib.request import getproxies
    if proxy is None:
        return None
    if isinstance(proxy, str):
        return proxy
    if proxy is True:
        proxies = getproxies()
        return (
            proxies.get("wss" if secure else "ws")
            or proxies.get("https" if secure else "http")
        )
    raise InvalidProxy(str(proxy), "proxy must be None, True, or a proxy URL")


class _Connect:
    def __init__(
        self,
        uri: str,
        *,
        options: dict[str, Any],
        **kwargs: Any,
    ):
        self.uri = uri
        self.options = options
        self.kwargs = kwargs
        self._connection: Optional[ClientConnection] = None
        self._backoff = 1.0

    def __await__(self) -> Generator[Any, None, ClientConnection]:
        return self._connect().__await__()

    async def __aenter__(self) -> ClientConnection:
        self._connection = await self._connect()
        return self._connection

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._connection is not None:
            await self._connection.close()
            self._connection = None

    def __aiter__(self) -> _Connect:
        return self

    async def __anext__(self) -> ClientConnection:
        if self._connection is not None:
            await self._connection.close()
            self._connection = None
        while True:
            try:
                connection = await self._connect()
            except Exception as exc:
                processed = self.options["process_exception"](exc)
                if processed is not None:
                    raise processed
                await asyncio.sleep(self._backoff)
                self._backoff = min(self._backoff * 2, 60.0)
                continue
            self._connection = connection
            self._backoff = 1.0
            return connection

    async def _connect(self) -> ClientConnection:
        parsed = parse_url(self.uri)
        proxy = _process_proxy(self.options["proxy"], parsed.is_secure)
        extra_headers = self._build_headers()
        max_message_size, max_frame_size = normalize_max_size(self.options["max_size"])
        connection_max_message_size = 0 if max_message_size is None else max_message_size

        if self.options["extensions"] is not None:
            raise NotImplementedError("custom extensions aren't supported by picows.websockets")
        if self.options["compression"] not in (None, "deflate"):
            raise NotImplementedError("only compression=None or 'deflate' are accepted")

        conn_kwargs = dict(self.kwargs)
        ssl_context = conn_kwargs.pop("ssl", None)
        host_override = conn_kwargs.pop("host", None)
        port_override = conn_kwargs.pop("port", None)
        preexisting_sock = conn_kwargs.pop("sock", None)

        socket_factory = conn_kwargs.pop("socket_factory", None)
        if preexisting_sock is not None:
            if socket_factory is not None:
                raise TypeError("cannot pass both sock and socket_factory")
            if not isinstance(preexisting_sock, socket.socket):
                raise TypeError("sock must be a socket.socket instance")

            provided_sock = preexisting_sock

            def provided_socket(_: Any) -> socket.socket:
                return provided_sock

            socket_factory = provided_socket
        elif host_override is not None or port_override is not None:
            if socket_factory is not None:
                raise TypeError("cannot pass both host/port override and socket_factory")

            async def connect_override(_: Any) -> socket.socket:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                await asyncio.get_running_loop().sock_connect(
                    sock,
                    (host_override or parsed.host, port_override or parsed.port),
                )
                return sock

            socket_factory = connect_override

        def listener_factory(
            request: picows.WSUpgradeRequest,
            response: picows.WSUpgradeResponse,
        ) -> ClientConnection:
            wrapped_request = Request.from_picows(request)
            wrapped_response = Response.from_picows(response)
            subprotocol = resolve_subprotocol(self.options["subprotocols"], wrapped_response)
            permessage_deflate = configure_permessage_deflate(wrapped_response, self.options["compression"])
            logger = resolve_logger(self.options["logger"], "websockets.client")
            return ClientConnection(
                request=wrapped_request,
                response=wrapped_response,
                subprotocol=subprotocol,
                permessage_deflate=permessage_deflate,
                ping_interval=self.options["ping_interval"],
                ping_timeout=self.options["ping_timeout"],
                close_timeout=self.options["close_timeout"],
                max_queue=self.options["max_queue"],
                write_limit=self.options["write_limit"],
                max_message_size=connection_max_message_size,
                max_frame_size=max_frame_size,
                logger=logger,
            )

        try:
            logger_name: Any = resolve_logger(self.options["logger"], "websockets.client")
            _transport, listener = await picows.ws_connect(
                listener_factory,
                self.uri,
                ssl_context=self._coerce_ssl_context(ssl_context),
                websocket_handshake_timeout=self.options["open_timeout"],
                enable_auto_ping=False,
                enable_auto_pong=True,
                max_frame_size=max_frame_size,
                extra_headers=extra_headers,
                proxy=proxy,
                socket_factory=socket_factory,
                logger_name=logger_name,
                **conn_kwargs,
            )
        except picows.WSInvalidURL as exc:
            raise InvalidURI(exc.args[0], exc.args[1] if len(exc.args) > 1 else str(exc)) from exc
        except picows.WSInvalidStatusError as exc:
            raise InvalidStatus(exc.response) from exc
        except picows.WSInvalidUpgradeError as exc:
            raise InvalidUpgrade(exc.name, exc.value) from exc
        except picows.WSInvalidHeaderError as exc:
            raise InvalidHeader(exc.name, exc.value) from exc
        except picows.WSInvalidMessageError as exc:
            raise InvalidMessage(str(exc)) from exc
        except picows.WSHandshakeError as exc:
            raise InvalidHandshake(str(exc)) from exc
        assert isinstance(listener, ClientConnection)
        return listener

    def _build_headers(self) -> list[tuple[str, str]]:
        headers = _header_items(self.options["additional_headers"])
        if self.options["origin"] is not None:
            headers.append(("Origin", self.options["origin"]))
        if self.options["user_agent_header"] is not None:
            headers.append(("User-Agent", self.options["user_agent_header"]))
        if self.options["subprotocols"]:
            headers.append(("Sec-WebSocket-Protocol", ", ".join(self.options["subprotocols"])))
        if self.options["compression"] == "deflate":
            headers.append(("Sec-WebSocket-Extensions", _PERMESSAGE_DEFLATE_REQUEST))
        return headers

    def _coerce_ssl_context(self, value: Any) -> Optional[SSLContext]:
        if value in (None, True):
            return None
        if value is False:
            raise NotImplementedError("ssl=False isn't supported for wss:// URIs")
        if not isinstance(value, SSLContext):
            raise TypeError("ssl must be an SSLContext, True, False, or None")
        return value


def connect(
    uri: str,
    *,
    origin: Optional[Origin] = None,
    extensions: Optional[Sequence[Any]] = None,
    subprotocols: Optional[Sequence[Subprotocol]] = None,
    compression: Optional[str] = "deflate",
    additional_headers: Optional[HeadersLike] = None,
    user_agent_header: Optional[str] = default_user_agent(),
    proxy: Union[str, bool, None] = True,
    process_exception: Callable[[Exception], Optional[Exception]] = process_exception,
    open_timeout: Optional[float] = 10,
    ping_interval: Optional[float] = 20,
    ping_timeout: Optional[float] = 20,
    close_timeout: Optional[float] = 10,
    max_size: MaxSize = 1024 * 1024,
    max_queue: Union[int, tuple[Optional[int], Optional[int]], None] = 16,
    write_limit: Union[int, tuple[int, Optional[int]]] = 32768,
    logger: LoggerLike = None,
    create_connection: Any = None,
    **kwargs: Any,
) -> _Connect:
    if create_connection is not None:
        raise NotImplementedError("create_connection isn't supported by picows.websockets yet")
    options = {
        name: value
        for name, value in locals().items()
        if name not in ("uri", "kwargs", "create_connection")
    }
    return _Connect(uri, options=options, **kwargs)
