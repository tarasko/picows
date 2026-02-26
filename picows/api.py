import asyncio
import socket
import urllib.parse
from dataclasses import dataclass
from inspect import isawaitable
from logging import getLogger
from ssl import SSLContext
from typing import Callable, Optional, Union, Dict, Any, Awaitable

from python_socks.async_.asyncio import Proxy

from .types import (WSHeadersLike, WSUpgradeRequest, WSHost, WSPort,
                    WSUpgradeResponseWithListener, WSUpgradeFailure)
from .picows import (WSListener, WSTransport, WSAutoPingStrategy,   # type: ignore [attr-defined]
                     WSProtocol)
from .url import parse_url, WSInvalidURL, WSParsedURL

from .sslproto import SSLProtocol


WSListenerFactory = Callable[[], WSListener]
WSServerListenerFactory = Callable[[WSUpgradeRequest], Union[WSListener, WSUpgradeResponseWithListener, None]]
WSSocketFactory = Callable[[WSParsedURL], Union[Optional[socket.socket], Awaitable[Optional[socket.socket]]]]


def _maybe_handle_redirect(exc: WSUpgradeFailure, old_parsed_url: WSParsedURL, max_redirects: int) -> WSParsedURL:
    if max_redirects <= 0:
        raise exc
    if exc.response is None:
        raise exc
    if exc.response.status not in (301, 302, 303, 307, 308):
        raise exc

    location = exc.response.headers.get("Location")

    if location is None:
        raise WSUpgradeFailure("received redirect HTTP response without Location header",
                       exc.raw_header, exc.raw_body, exc.response) from exc

    url = urllib.parse.urljoin(old_parsed_url.url, location)
    parsed_url = parse_url(url)

    if old_parsed_url.is_secure and not parsed_url.is_secure:
        raise WSUpgradeFailure(
            f"cannot follow redirect to non-secure URL {parsed_url.url}",
            exc.raw_header, exc.raw_body, exc.response)

    return parsed_url


def _is_connected(sock: socket.socket) -> bool:
    try:
        sock.getpeername()
        return True
    except OSError:
        return False

@dataclass
class _ConnectedSocket:
    sock: Optional[socket.socket]
    host: Optional[WSHost]
    port: Optional[WSPort]


async def _create_connected_socket(
        loop: asyncio.AbstractEventLoop,
        socket_factory: Optional[WSSocketFactory],
        parsed_url: WSParsedURL
) -> Optional[socket.socket]:
    if socket_factory is None:
        return None

    sock_or_awaitable = socket_factory(parsed_url)
    if isawaitable(sock_or_awaitable):
        sock = await sock_or_awaitable
    else:
        sock = sock_or_awaitable

    if sock is not None:
        sock.setblocking(False)
    if sock is not None:
        if not _is_connected(sock):
            await loop.sock_connect(sock, (parsed_url.host, parsed_url.port))

    return sock


async def _connect_through_optional_proxy(
        loop: asyncio.AbstractEventLoop,
        parsed_url: WSParsedURL,
        proxy_parsed_url: Optional[WSParsedURL],
        socket_factory: Optional[WSSocketFactory],
        ssl_context: Optional[Union[SSLContext, bool]],
        conn_kwargs: Dict[str, Any]
) -> _ConnectedSocket:
    if proxy_parsed_url is not None and proxy_parsed_url.scheme == "https":
        raise WSInvalidURL(proxy_parsed_url.url,
            "HTTPS proxy URL scheme is not supported, use http://, socks4:// or socks5://")

    if proxy_parsed_url is not None:
        proxy_obj = Proxy.from_url(proxy_parsed_url.url, loop=loop)
        proxy_socket = await _create_connected_socket(loop, socket_factory, proxy_parsed_url)
        if proxy_socket is not None:
            # It is so ugly that I have to use python_socks internals
            # I could not figure out how to pass existing connected socket using public
            # interface. Maybe I should just copy that part of the code?

            # Import everthing as local as possible
            # If imports will stop working, picows ws_connect will break but only
            # if user has passed proxy together with socket_factory

            from python_socks import ProxyError
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
            except ReplyError as e:
                await stream.close() # type: ignore[no-untyped-call]
                raise ProxyError(e, error_code=e.error_code) # type: ignore[no-untyped-call]
            except (asyncio.CancelledError, Exception):
                await stream.close() # type: ignore[no-untyped-call]
                raise
        else:
            proxy_socket = await proxy_obj.connect(
                dest_host=parsed_url.host,
                dest_port=parsed_url.port,
            )

        if ssl_context and "server_hostname" not in conn_kwargs:
            conn_kwargs["server_hostname"] = parsed_url.host

        return _ConnectedSocket(proxy_socket, None, None)
    else:
        sock = await _create_connected_socket(loop, socket_factory, parsed_url)
        if sock is not None:
            if ssl_context and "server_hostname" not in conn_kwargs:
                conn_kwargs["server_hostname"] = parsed_url.host

            return _ConnectedSocket(sock, None, None)
        else:
            return _ConnectedSocket(None, parsed_url.host, parsed_url.port)


async def ws_connect(ws_listener_factory: WSListenerFactory, # type: ignore [no-untyped-def]
                     url: str,
                     *,
                     ssl_context: Optional[SSLContext] = None,
                     disconnect_on_exception: bool = True,
                     websocket_handshake_timeout: float = 5,
                     logger_name: str = "client",
                     enable_auto_ping: bool = False,
                     auto_ping_idle_timeout: float = 10,
                     auto_ping_reply_timeout: float = 10,
                     auto_ping_strategy: WSAutoPingStrategy = WSAutoPingStrategy.PING_WHEN_IDLE,
                     enable_auto_pong: bool = True,
                     max_frame_size: int = 10 * 1024 * 1024,
                     extra_headers: Optional[WSHeadersLike] = None,
                     max_redirects: int = 5,
                     proxy: Optional[str] = None,
                     read_buffer_init_size: int = 16 * 1024,
                     socket_factory: Optional[WSSocketFactory] = None,
                     **kwargs
                     ) -> tuple[WSTransport, WSListener]:
    """
    Open a WebSocket connection to a given URL.

    This function forwards its `kwargs` directly to
    `asyncio.loop.create_connection <https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_connection>`_

    :param ws_listener_factory:
        A parameterless factory function that returns a user handler.
        User handler has to derive from :any:`WSListener`.
    :param url: Destination URL
    :param ssl_context: optional SSLContext to override default one when
        the wss scheme is used
    :param disconnect_on_exception:
        Indicates whether the client should initiate disconnect on any exception
        thrown from WSListener.on_ws_frame callbacks
    :param websocket_handshake_timeout:
        is the time in seconds to wait for the websocket client to receive
        websocket handshake response before aborting the connection.
    :param logger_name:
        picows will use `picows.<logger_name>` logger to do all the logging.
    :param enable_auto_ping:
        Enable detection of a stale connection by periodically pinging remote peer.

        .. note::
            This does NOT enable automatic replies to incoming `ping` requests.
            enable_auto_pong argument controls it.
    :param auto_ping_idle_timeout:
        * when auto_ping_strategy == PING_WHEN_IDLE
            how long to wait before sending `ping` request when there is no incoming data.
        * when auto_ping_strategy == PING_PERIODICALLY
            how often to send ping
    :param auto_ping_reply_timeout:
        how long to wait for a `pong` reply before shutting down connection.
    :param auto_ping_strategy:
        An :any:`WSAutoPingStrategy` enum value:

        * PING_WHEN_IDLE - ping only if there is no new incoming data.
        * PING_PERIODICALLY - send ping at regular intervals regardless of incoming data.
    :param enable_auto_pong:
        If enabled, picows will automatically reply to incoming PING frames.
    :param max_frame_size:
        * Maximum allowed frame size. Disconnect will be initiated if client receives a frame that is bigger than max size.
    :param extra_headers:
        Arbitrary HTTP headers to add to the handshake request.
    :param max_redirects:
        * How many times we can follow HTTP redirects. Set to 0 in order to disable redirects.
    :param proxy:
        Optional proxy URL. Supported schemes are ``http://``, ``socks4://``
        and ``socks5://`` (including authenticated variants).
        HTTPS proxy scheme (``https://``) is currently not supported.
    :param read_buffer_init_size:
        Initial size (in bytes) of the internal read buffer.
        The buffer grows exponentially when incoming data does not fit.
        Unlike `max_frame_size` (a safety limit), this value affects actual
        memory allocation, so very large values increase baseline memory usage.
    :param socket_factory:
        Optional socket factory. Can be a regular function or coroutine.
        Receive WSParsedURL object as the only argument. Returns pre-created socket.
        Returning ``None`` falls back to the default connection path.

        The returned socket may be either already connected to the provided
        endpoint or unconnected. If unconnected, picows will connect it.

        If ``proxy`` is set, ``WSParsedURL`` passed to the factory is proxy
        endpoint coordinates, not final WebSocket server coordinates.
    :return: :any:`WSTransport` object and a user handler returned by `ws_listener_factory()`
    """

    assert "ssl" not in kwargs, "explicit 'ssl' argument for loop.create_connection is not supported"
    assert "sock" not in kwargs, "explicit 'sock' argument for loop.create_connection is not supported"
    assert "all_errors" not in kwargs, "explicit 'all_errors' argument for loop.create_connection is not supported"
    assert auto_ping_strategy in (WSAutoPingStrategy.PING_WHEN_IDLE, WSAutoPingStrategy.PING_PERIODICALLY), \
        "invalid value of auto_ping_strategy parameter"

    # May sure people who are passing old argument are not going to get an exception
    kwargs.pop('zero_copy_unsafe_ssl_write', None)

    logger = getLogger(f"picows.{logger_name}")
    parsed_url = parse_url(url)
    parsed_proxy_url = parse_url(proxy, False) if proxy is not None else None
    loop = asyncio.get_running_loop()

    while True:
        if parsed_url.username is not None or parsed_url.password is not None:
            logger.warning("Basic authentication was requested in URL, but it is not currently supported, ignore username and password")

        if parsed_url.is_secure:
            ssl = ssl_context if ssl_context is not None else True
        else:
            ssl = None

        def ws_protocol_factory() -> WSProtocol:
            return WSProtocol(
                parsed_url.netloc,
                parsed_url.resource_name,
                True,
                ws_listener_factory,
                logger,
                disconnect_on_exception,
                websocket_handshake_timeout,
                enable_auto_ping,
                auto_ping_idle_timeout,
                auto_ping_reply_timeout,
                auto_ping_strategy,
                enable_auto_pong,
                max_frame_size,
                extra_headers,
                read_buffer_init_size
            )

        try:
            conn_kwargs = dict(kwargs)
            conn_socket = await _connect_through_optional_proxy(
                loop, parsed_url, parsed_proxy_url, socket_factory, ssl, conn_kwargs)

            if ssl:
                server_hostname = conn_kwargs.pop('server_hostname', None)
                ssl_handshake_timeout = conn_kwargs.pop('ssl_handshake_timeout', None)
                ssl_shutdown_timeout = conn_kwargs.pop('ssl_shutdown_timeout', None)
                ssl_protocol: SSLProtocol

                def ssl_protocol_factory():
                    ws_protocol = ws_protocol_factory()

                    return SSLProtocol(ws_protocol, ssl,
                                       False,
                                       parsed_url.host,
                                       True,
                                       ssl_handshake_timeout,
                                       ssl_shutdown_timeout
                                       )

                (_, ssl_protocol) = await loop.create_connection(
                    ssl_protocol_factory,
                    conn_socket.host,       # type: ignore[arg-type]
                    conn_socket.port,       # type: ignore[arg-type]
                    sock=conn_socket.sock,  # type: ignore[arg-type]
                    **conn_kwargs
                )

                await ssl_protocol.ssl_handshake_complete_fut
                ws_protocol = ssl_protocol.get_app_protocol()
            else:
                (_, ws_protocol) = await loop.create_connection(
                    ws_protocol_factory,
                    conn_socket.host,       # type: ignore[arg-type]
                    conn_socket.port,       # type: ignore[arg-type]
                    sock=conn_socket.sock,  # type: ignore[arg-type]
                    **conn_kwargs
                )

            await ws_protocol.wait_until_handshake_complete()
            return ws_protocol.transport, ws_protocol.listener
        except WSUpgradeFailure as exc:
            new_parsed_url = _maybe_handle_redirect(exc, parsed_url, max_redirects)
            logger.info("%s replied with HTTP redirect to %s, (status = %s)",
                        parsed_url.url, new_parsed_url.url, exc.response.status) # type: ignore [union-attr]
            parsed_url = new_parsed_url
            max_redirects -= 1


async def ws_create_server(ws_listener_factory: WSServerListenerFactory,        # type: ignore [no-untyped-def]
                           host=None,
                           port=None,
                           *,
                           disconnect_on_exception: bool = True,
                           websocket_handshake_timeout=5,
                           logger_name: str = "server",
                           enable_auto_ping: bool = False,
                           auto_ping_idle_timeout: float = 20,
                           auto_ping_reply_timeout: float = 20,
                           auto_ping_strategy=WSAutoPingStrategy.PING_WHEN_IDLE,
                           enable_auto_pong: bool = True,
                           max_frame_size: int = 10 * 1024 * 1024,
                           read_buffer_init_size: int = 16 * 1024,
                           **kwargs
                           ) -> asyncio.Server:
    """
    Create a WebSocket server listening on a TCP port at the host address.
    This function forwards its `kwargs` directly to
    `asyncio.loop.create_server <https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_server>`_

    It has a few extra parameters to control WebSocket behavior.

    :param ws_listener_factory:
        A factory function that accepts WSUpgradeRequest object and returns one of:

        * User handler object. A standard 101 response will be sent to the client.
        * WSUpgradeResponseWithListener object. This allows to send a custom response with extra headers and an optional body.
        * None. In such case 404 Not Found response will be sent and the client will be disconnected.

        The user handler must derive from WSListener and is responsible for
        processing incoming data.

        The factory function acts as a router. :any:`WSUpgradeRequest` contains the
        requested path and headers. Different user listeners may be returned
        depending on the path and other conditions.
    :param host:
        The host parameter can be set to several types which determine where the server would be listening:

        * If host is a string, the TCP server is bound to a single network interface specified by host.
        * If host is a sequence of strings, the TCP server is bound to all network interfaces specified by the sequence.
        * If host is an empty string or None, all interfaces are assumed and a list of multiple sockets will be returned (most likely one for IPv4 and another one for IPv6).
    :param port: specify which port the server should listen on.
        If 0 or None (the default), a random unused port will be selected
        (note that if host resolves to multiple network interfaces,
        a different random port will be selected for each interface).
    :param disconnect_on_exception:
        Indicates whether the client should initiate disconnect on any exception
        thrown by WSListener.on_ws_frame callback
    :param websocket_handshake_timeout:
        is the time in seconds to wait for the websocket server to receive websocket handshake request before aborting the connection.
    :param logger_name:
        picows will use `picows.<logger_name>` logger to do all the logging.
    :param enable_auto_ping:
        Enable detection of a stale connection by periodically pinging remote peer.

        .. note::
            This does NOT enable automatic replies to incoming `ping` requests.
            enable_auto_pong argument controls it.
    :param auto_ping_idle_timeout:
        * when auto_ping_strategy == PING_WHEN_IDLE
            how long to wait before sending `ping` request when there is no incoming data.
        * when auto_ping_strategy == PING_PERIODICALLY
            how often to send ping
    :param auto_ping_reply_timeout:
        how long to wait for a `pong` reply before shutting down connection.
    :param auto_ping_strategy:
        An :any:`WSAutoPingStrategy` enum value:

        * PING_WHEN_IDLE - ping only if there is no new incoming data.
        * PING_PERIODICALLY - send ping at regular intervals regardless of incoming data.
    :param enable_auto_pong:
        If enabled, picows will automatically reply to incoming PING frames.
    :param max_frame_size:
        * Maximum allowed frame size. Disconnect will be initiated if the server side receives a frame that is bigger than the max size.
    :param read_buffer_init_size:
        Initial size of the internal read buffer. The buffer grows exponentially if new data doesn't fit.
        You may set this to the actual expected maximum frame size but don't push it too much. Contrary to `max_frame_size` which
        is just a safety check, setting big value here will force **picows** to actually allocate the specified amount of memory.
    :return: `asyncio.Server <https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.Server>`_ object
    """

    assert auto_ping_strategy in (WSAutoPingStrategy.PING_WHEN_IDLE, WSAutoPingStrategy.PING_PERIODICALLY), "invalid value of auto_ping_strategy parameter"

    # May sure people who are passing old argument are not going to get an exception
    kwargs.pop('zero_copy_unsafe_ssl_write', None)

    def ws_protocol_factory() -> WSProtocol:
        return WSProtocol(
            None,           # host+port
            None,           # ws_path
            False,          # is_client_side
            ws_listener_factory,
            getLogger(f"picows.{logger_name}"),
            disconnect_on_exception,
            websocket_handshake_timeout,
            enable_auto_ping, auto_ping_idle_timeout, auto_ping_reply_timeout,
            auto_ping_strategy,
            enable_auto_pong,
            max_frame_size,
            None,            # extra_headers,
            read_buffer_init_size
        )

    ssl = kwargs.pop('ssl', None)
    ssl_handshake_timeout = kwargs.pop('ssl_handshake_timeout', None)
    ssl_shutdown_timeout = kwargs.pop('ssl_shutdown_timeout', None)

    if not ssl:
        return await asyncio.get_running_loop().create_server(
            ws_protocol_factory,
            host=host,
            port=port,
            **kwargs)

    def ssl_protocol_factory():
        ws_protocol = ws_protocol_factory()
        ssl_protocol = SSLProtocol(ws_protocol, ssl, True, None, True, ssl_handshake_timeout, ssl_shutdown_timeout)
        return ssl_protocol

    return await asyncio.get_running_loop().create_server(
        ssl_protocol_factory,
        host=host,
        port=port,
        **kwargs)

