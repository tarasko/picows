import asyncio
import base64
import socket
import ssl as ssl_module
import urllib.parse
from dataclasses import dataclass
from inspect import isawaitable
from ssl import SSLContext
from typing import Any, Awaitable, Callable, Dict, Optional, Union, cast

from python_socks import ProxyError
from python_socks.async_.asyncio import Proxy

from .common import WSHost, WSPort
from .url import WSParsedURL


WSSocketFactory = Callable[[WSParsedURL], Union[Optional[socket.socket], Awaitable[Optional[socket.socket]]]]


_MAX_PROXY_RESPONSE_SIZE = 64 * 1024


def _format_authority(host: WSHost, port: WSPort) -> str:
    if ":" in host and not host.startswith("["):
        host = WSHost(f"[{host}]")
    return f"{host}:{port}"


class HTTPProxyConnectProtocol(asyncio.Protocol):
    def __init__(
            self,
            host: WSHost,
            port: WSPort,
            username: Optional[str],
            password: Optional[str]
    ) -> None:
        self._authority = _format_authority(host, port)
        self._username = username
        self._password = password
        self._transport: Optional[asyncio.Transport] = None
        self._response = bytearray()
        self._tunnel_established = asyncio.get_running_loop().create_future()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.Transport, transport)

        request = (
            f"CONNECT {self._authority} HTTP/1.1\r\n"
            f"Host: {self._authority}\r\n"
        ).encode("ascii")

        if self._username is not None:
            username = urllib.parse.unquote(self._username)
            password = urllib.parse.unquote(self._password or "")
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            request += f"Proxy-Authorization: Basic {credentials}\r\n".encode("ascii")

        self._transport.write(request + b"\r\n")

    def data_received(self, data: bytes) -> None:
        if self._tunnel_established.done():
            return

        self._response.extend(data)
        header_end = self._response.find(b"\r\n\r\n")
        if header_end == -1:
            if len(self._response) > _MAX_PROXY_RESPONSE_SIZE:
                self._fail(ProxyError("HTTP proxy response headers are too large"))
            return
        if header_end + 4 > _MAX_PROXY_RESPONSE_SIZE:
            self._fail(ProxyError("HTTP proxy response headers are too large"))
            return

        status_line = bytes(self._response[:header_end]).split(b"\r\n", 1)[0]
        parts = status_line.split(b" ", 2)
        try:
            if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
                raise ValueError
            status = int(parts[1])
        except ValueError:
            self._fail(ProxyError("HTTP proxy returned an invalid response"))
            return

        if 200 <= status < 300:
            self._tunnel_established.set_result(None)
        else:
            self._fail(ProxyError(f"HTTP proxy rejected connection with status {status}"))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self._tunnel_established.done():
            return

        if exc is None:
            exc = ProxyError("HTTP proxy closed the connection before replying")

        self._tunnel_established.set_exception(exc)

    def _fail(self, exc: Exception) -> None:
        if self._transport is not None:
            self._transport.abort()
        self._tunnel_established.set_exception(exc)

    async def wait_tunnel_established(self) -> None:
        await self._tunnel_established


@dataclass(frozen=True)
class ConnectedSocket:
    sock: Optional[socket.socket]
    host: Optional[WSHost]
    port: Optional[WSPort]


@dataclass(frozen=True)
class ConnectedTransport:
    transport: asyncio.Transport


def _is_connected(sock: socket.socket) -> bool:
    try:
        sock.getpeername()
        return True
    except OSError:
        return False


async def _create_connected_socket(
        loop: asyncio.AbstractEventLoop,
        socket_factory: Optional[WSSocketFactory],
        parsed_url: WSParsedURL
) -> Optional[socket.socket]:
    if socket_factory is None:
        return None

    sock_or_awaitable = socket_factory(parsed_url)
    sock: Optional[socket.socket]
    if sock_or_awaitable is None or isinstance(sock_or_awaitable, socket.socket):
        sock = sock_or_awaitable
    elif isawaitable(sock_or_awaitable):
        sock = await sock_or_awaitable
    else:
        raise TypeError(f"user socket_factory() returned invalid type: {type(sock_or_awaitable).__name__}")

    if sock is not None:
        sock.setblocking(False)
        if not _is_connected(sock):
            await loop.sock_connect(sock, (parsed_url.host, parsed_url.port))

    return sock


async def connect_through_optional_proxy(
        loop: asyncio.AbstractEventLoop,
        parsed_url: WSParsedURL,
        proxy_parsed_url: Optional[WSParsedURL],
        socket_factory: Optional[WSSocketFactory],
        ssl_context: Optional[Union[SSLContext, bool]],
        proxy_ssl_context: Optional[SSLContext],
        conn_kwargs: Dict[str, Any],
        create_connection: Callable[..., Awaitable[Any]]
) -> Union[ConnectedSocket, ConnectedTransport]:
    if proxy_parsed_url is None:
        sock = await _create_connected_socket(loop, socket_factory, parsed_url)
        if sock is not None:
            if ssl_context and "server_hostname" not in conn_kwargs:
                conn_kwargs["server_hostname"] = parsed_url.host

            return ConnectedSocket(sock, None, None)
        return ConnectedSocket(None, parsed_url.host, parsed_url.port)

    if proxy_parsed_url.scheme in ("http", "https"):
        proxy_socket = await _create_connected_socket(loop, socket_factory, proxy_parsed_url)
        proxy_conn_kwargs = {
            key: value for key, value in conn_kwargs.items()
            if key != "server_hostname" and not key.startswith("ssl_")
        }

        if proxy_parsed_url.scheme == "https":
            if proxy_ssl_context is None:
                proxy_ssl_context = ssl_module.create_default_context()
            proxy_server_hostname: Optional[str] = proxy_parsed_url.host
        else:
            if proxy_ssl_context is not None:
                raise ValueError("proxy_ssl_context is only supported for https:// proxies")
            proxy_server_hostname = None

        def proxy_protocol_factory() -> HTTPProxyConnectProtocol:
            return HTTPProxyConnectProtocol(
                parsed_url.host,
                parsed_url.port,
                proxy_parsed_url.username,
                proxy_parsed_url.password,
            )

        if proxy_socket is None:
            proxy_host: Optional[WSHost] = proxy_parsed_url.host
            proxy_port: Optional[WSPort] = proxy_parsed_url.port
        else:
            proxy_host = None
            proxy_port = None

        transport, proxy_protocol = await create_connection(
            proxy_protocol_factory,
            proxy_host,
            proxy_port,
            ssl=proxy_ssl_context,
            sock=proxy_socket,
            server_hostname=proxy_server_hostname,
            **proxy_conn_kwargs,
        )
        try:
            await proxy_protocol.wait_tunnel_established()
        except (asyncio.CancelledError, Exception):
            transport.abort()
            raise

        return ConnectedTransport(transport)

    # SOCKS4 and SOCKS5 proxies return an already connected socket that can be
    # passed to loop.create_connection.
    proxy_obj = Proxy.from_url(proxy_parsed_url.url, loop=loop)
    proxy_socket = await _create_connected_socket(loop, socket_factory, proxy_parsed_url)
    if proxy_socket is not None:
        # There is no public python-socks interface for passing an existing
        # connected socket, so keep the private imports local to this path.
        from python_socks._connectors.factory_async import create_connector
        from python_socks._protocols.errors import ReplyError
        from python_socks.async_.asyncio._stream import AsyncioSocketStream

        stream = AsyncioSocketStream(sock=proxy_socket, loop=loop)

        try:
            connector = create_connector(
                proxy_type=proxy_obj._proxy_type,
                username=proxy_obj._username,
                password=proxy_obj._password,
                rdns=proxy_obj._rdns,
                resolver=proxy_obj._resolver,
            )
            await connector.connect(
                stream=stream,
                host=parsed_url.host,
                port=parsed_url.port,
            )
        except ReplyError as exc:
            await stream.close()
            raise ProxyError(exc, error_code=exc.error_code)
        except (asyncio.CancelledError, Exception):
            await stream.close()
            raise
    else:
        proxy_socket = await proxy_obj.connect(
            dest_host=parsed_url.host,
            dest_port=parsed_url.port,
        )

    if ssl_context and "server_hostname" not in conn_kwargs:
        conn_kwargs["server_hostname"] = parsed_url.host

    return ConnectedSocket(proxy_socket, None, None)
