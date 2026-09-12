import asyncio
import ssl as ssl_module
import urllib.parse
from functools import partial
from logging import Logger, LoggerAdapter, getLogger
from ssl import SSLContext
from typing import Any, Awaitable, Callable, Optional, Union, cast, TYPE_CHECKING

from .proxy import (ConnectedTransport, WSSocketFactory,
                    connect_through_optional_proxy)
from .common import (WSHeadersLike, WSUpgradeRequest, WSUpgradeResponse,
                     WSUpgradeResponseWithListener, WSHandshakeError)
from .picows import (WSListener, WSTransport, WSAutoPingStrategy,   # type: ignore [attr-defined]
                     WSProtocol)
from .url import parse_url, WSParsedURL

WSListenerFactory = Union[
    Callable[[], WSListener],
    Callable[[WSUpgradeRequest, WSUpgradeResponse], WSListener],
]
WSServerListenerFactory = Callable[[WSUpgradeRequest], Union[WSListener, WSUpgradeResponseWithListener, None]]

if TYPE_CHECKING:
    _WSLoggerAdapter = LoggerAdapter[Any]
else:
    _WSLoggerAdapter = LoggerAdapter

WSLoggerLike = Union[str, Logger, _WSLoggerAdapter, None]

_HAS_AIOFASTNET = False
try:
    import aiofastnet
    _HAS_AIOFASTNET = True
except ImportError:
    pass


def _maybe_handle_redirect(exc: WSHandshakeError, old_parsed_url: WSParsedURL, max_redirects: int) -> WSParsedURL:
    if max_redirects <= 0:
        raise exc
    if exc.response is None:
        raise exc
    if exc.response.status not in (301, 302, 303, 307, 308):
        raise exc

    location = exc.response.headers.get("Location")

    if location is None:
        raise WSHandshakeError("received redirect HTTP response without Location header",
                               exc.raw_header, exc.raw_body, exc.response) from exc

    url = urllib.parse.urljoin(old_parsed_url.url, location)
    parsed_url = parse_url(url)

    if old_parsed_url.is_secure and not parsed_url.is_secure:
        raise WSHandshakeError(
            f"cannot follow redirect to non-secure URL {parsed_url.url}",
            exc.raw_header, exc.raw_body, exc.response)

    return parsed_url


def _resolve_logger(
        logger_name: WSLoggerLike,
        default_suffix: str,
        prefix: str = "picows."
) -> Union[Logger, _WSLoggerAdapter]:
    if logger_name is None:
        return getLogger(f"{prefix}{default_suffix}")

    if isinstance(logger_name, str):
        return getLogger(f"{prefix}{logger_name}")

    return logger_name


async def ws_connect(ws_listener_factory: WSListenerFactory, # type: ignore [no-untyped-def]
                     url: str,
                     *,
                     ssl_context: Optional[SSLContext] = None,
                     disconnect_on_exception: bool = True,
                     websocket_handshake_timeout: Optional[float] = 5,
                     logger_name: WSLoggerLike = None,
                     enable_auto_ping: bool = False,
                     auto_ping_idle_timeout: float = 10,
                     auto_ping_reply_timeout: float = 10,
                     auto_ping_strategy: WSAutoPingStrategy = WSAutoPingStrategy.PING_WHEN_IDLE,
                     enable_auto_pong: bool = True,
                     max_frame_size: int = 10 * 1024 * 1024,
                     extra_headers: Optional[WSHeadersLike] = None,
                     max_redirects: int = 5,
                     proxy: Optional[str] = None,
                     proxy_ssl_context: Optional[SSLContext] = None,
                     read_buffer_init_size: int = 16 * 1024,
                     socket_factory: Optional[WSSocketFactory] = None,
                     use_aiofastnet: Optional[bool] = None,
                     **kwargs
                     ) -> tuple[WSTransport, WSListener]:
    """
    Open a WebSocket connection to a given URL.

    This function forwards its `kwargs` directly to
    `asyncio.loop.create_connection <https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_connection>`_

    :param ws_listener_factory:
        A factory function that returns a user handler.
        The factory may either accept no arguments, or accept the negotiated
        :any:`WSUpgradeRequest` and :any:`WSUpgradeResponse`.
        The returned handler has to derive from :any:`WSListener`.
    :param url: Destination URL
    :param ssl_context: optional SSLContext to override default one when
        the wss scheme is used
    :param disconnect_on_exception:
        Indicates whether the client should initiate disconnect on any exception
        thrown from WSListener.on_ws_frame callbacks
    :param websocket_handshake_timeout:
        is the time in seconds to wait for the websocket client to receive
        websocket handshake response before aborting the connection.
        Set to ``None`` to disable the timeout.
    :param logger_name:
        Logger name suffix or logger-like object used for logging.
        If a string is provided, picows will use `picows.<logger_name>`.
        If ``None`` is provided, picows will use ``picows.client``.
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
        ``Host`` is treated specially: it replaces the value generated from
        ``url`` instead of adding a second ``Host`` header. Header names are
        matched case-insensitively.
    :param max_redirects:
        * How many times we can follow HTTP redirects. Set to 0 in order to disable redirects.
    :param proxy:
        Optional proxy URL. Supported schemes are ``http://``, ``https://``,
        ``socks4://`` and ``socks5://`` (including authenticated variants).
    :param proxy_ssl_context:
        Optional SSLContext for the TLS connection to an ``https://`` proxy.
        A default client context is used when this isn't provided.
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
    :param use_aiofastnet:
        Use **aiofastnet** package to create client and server connections
        instead of ``loop.create_server``, ``loop.create_connection`` native method.
        **picows** will use **aiofastnet** by default if it is installed.
        You can override default behavior by using this argument.
    :return:
        :any:`WSTransport` object and a user handler returned by
        `ws_listener_factory()`, or by
        `ws_listener_factory(request, response)` when using the two-argument
        client factory form.
    """

    assert "ssl" not in kwargs, "explicit 'ssl' argument for loop.create_connection is not supported"
    assert "sock" not in kwargs, "explicit 'sock' argument for loop.create_connection is not supported"
    assert "all_errors" not in kwargs, "explicit 'all_errors' argument for loop.create_connection is not supported"
    assert auto_ping_strategy in (WSAutoPingStrategy.PING_WHEN_IDLE, WSAutoPingStrategy.PING_PERIODICALLY), \
        "invalid value of auto_ping_strategy parameter"
    assert _HAS_AIOFASTNET or use_aiofastnet != True, "use_aiofastnet==True, but aiofastnet package is not installed"

    if use_aiofastnet is None:
        use_aiofastnet = _HAS_AIOFASTNET

    # May sure people who are passing old argument are not going to get an exception
    kwargs.pop('zero_copy_unsafe_ssl_write', None)

    logger = _resolve_logger(logger_name, "client")
    parsed_url = parse_url(url)
    parsed_proxy_url = parse_url(proxy, False) if proxy is not None else None
    loop = asyncio.get_running_loop()

    start_tls: Callable[..., Awaitable[Optional[asyncio.Transport]]]
    if use_aiofastnet:
        create_connection = partial(aiofastnet.create_connection, loop)
        start_tls = partial(aiofastnet.start_tls, loop)
    else:
        create_connection = loop.create_connection # type: ignore [assignment]
        start_tls = loop.start_tls

    ssl: Optional[Union[SSLContext, bool]]
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
            connection = await connect_through_optional_proxy(
                loop, parsed_url, parsed_proxy_url, socket_factory, ssl,
                proxy_ssl_context, conn_kwargs, create_connection)

            if isinstance(connection, ConnectedTransport):
                transport = connection.transport
                try:
                    if ssl is not None:
                        target_ssl_context = ssl if isinstance(ssl, SSLContext) \
                            else ssl_module.create_default_context()
                        server_hostname = conn_kwargs.get("server_hostname", parsed_url.host)
                        start_tls_kwargs = {
                            key: value for key, value in conn_kwargs.items()
                            if key.startswith("ssl_")
                        }

                        new_transport = await start_tls(
                            transport, transport.get_protocol(), target_ssl_context,
                            server_hostname=server_hostname, **start_tls_kwargs)

                        # asyncio docs says that start_tls can potentially return None if transport
                        # is already closing
                        if new_transport is None:
                            raise ConnectionError("connection closed while starting TLS")

                        transport = new_transport

                    ws_protocol = ws_protocol_factory()
                    transport.set_protocol(ws_protocol)
                    ws_protocol.connection_made(transport)
                except (asyncio.CancelledError, Exception):
                    transport.abort()
                    raise
            else:
                (_, ws_protocol) = await create_connection(
                    ws_protocol_factory,
                    connection.host,
                    connection.port,
                    ssl=ssl,
                    sock=connection.sock,
                    **conn_kwargs
                    )

            await ws_protocol.wait_until_handshake_complete()
            return ws_protocol.transport, ws_protocol.listener
        except WSHandshakeError as exc:
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
                           websocket_handshake_timeout: Optional[float] = 5,
                           logger_name: WSLoggerLike = None,
                           enable_auto_ping: bool = False,
                           auto_ping_idle_timeout: float = 20,
                           auto_ping_reply_timeout: float = 20,
                           auto_ping_strategy=WSAutoPingStrategy.PING_WHEN_IDLE,
                           enable_auto_pong: bool = True,
                           max_frame_size: int = 10 * 1024 * 1024,
                           read_buffer_init_size: int = 16 * 1024,
                           use_aiofastnet: Optional[bool] = None,
                           **kwargs
                           ) -> asyncio.Server:
    """
    Create a WebSocket server listening on a TCP port at the host address.
    This function forwards its `kwargs` directly to
    `asyncio.loop.create_server <https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_server>`_

    It has a few extra parameters to control WebSocket behavior.

    :param ws_listener_factory:
        A factory function that accepts a parsed WSUpgradeRequest object before
        WebSocket upgrade headers are validated and returns one of:

        * User handler object. A standard 101 response will be sent to the client.
        * WSUpgradeResponseWithListener object. This allows to send a custom response with extra headers and an optional body.
        * None. In such case 404 Not Found response will be sent and the client will be disconnected.

        Returning a response whose status isn't 101 Switching Protocols sends
        that response with ``Connection: close``, without validating WebSocket
        upgrade headers, and then disconnects the client. Any user-provided
        ``Connection`` response header is overridden. This can be used for small
        HTTP endpoints such as health checks. A 101 response is sent only after
        validating the WebSocket upgrade request.

        Incoming requests must be HTTP/1.1 GET requests without a body.
        ``Content-Length`` may be omitted or set to zero; ``Transfer-Encoding``
        and non-zero content lengths are rejected.

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
        Set to ``None`` to disable the timeout.
    :param logger_name:
        Logger name suffix or logger-like object used for logging.
        If a string is provided, picows will use `picows.<logger_name>`.
        If ``None`` is provided, picows will use ``picows.server``.
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
    :param use_aiofastnet:
        Use **aiofastnet** package to create client and server connections
        instead of ``loop.create_server``, ``loop.create_connection`` native method.
        **picows** will use **aiofastnet** by default if it is installed.
        You can override default behavior by using this argument.
    :return: `asyncio.Server <https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.Server>`_ object
    """

    assert auto_ping_strategy in (WSAutoPingStrategy.PING_WHEN_IDLE, WSAutoPingStrategy.PING_PERIODICALLY), "invalid value of auto_ping_strategy parameter"
    assert _HAS_AIOFASTNET or use_aiofastnet != True, "use_aiofastnet==True, but aiofastnet package is not installed"

    if use_aiofastnet is None:
        use_aiofastnet = _HAS_AIOFASTNET

    # May sure people who are passing old argument are not going to get an exception
    kwargs.pop('zero_copy_unsafe_ssl_write', None)
    loop = asyncio.get_running_loop()
    if use_aiofastnet:
        create_server = partial(aiofastnet.create_server, loop)
    else:
        create_server = loop.create_server  # type: ignore [assignment]

    def ws_protocol_factory() -> WSProtocol:
        return WSProtocol(
            None,           # host+port
            None,           # ws_path
            False,          # is_client_side
            ws_listener_factory,
            _resolve_logger(logger_name, "server"),
            disconnect_on_exception,
            websocket_handshake_timeout,
            enable_auto_ping, auto_ping_idle_timeout, auto_ping_reply_timeout,
            auto_ping_strategy,
            enable_auto_pong,
            max_frame_size,
            None,            # extra_headers,
            read_buffer_init_size
        )

    server = await create_server(
        ws_protocol_factory,
        host=host,
        port=port,
        **kwargs)
    return server
