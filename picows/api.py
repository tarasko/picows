import asyncio
import ssl
import sys
import urllib.parse
from logging import getLogger
from ssl import SSLContext
from typing import Callable, Optional, Union

from python_socks.async_.asyncio import Proxy
from python_socks.async_.asyncio.v2 import Proxy as ProxyV2

from .types import (WSHeadersLike, WSUpgradeRequest,
                    WSUpgradeResponseWithListener, WSError)
from .picows import (WSListener, WSTransport, WSAutoPingStrategy,   # type: ignore [attr-defined]
                     WSProtocol)
from .url import parse_url, ParsedURL, WSInvalidURL

_proxy_stream_lifecycle_guards: set[object] = set()


def _maybe_handle_redirect(exc: WSError, old_parsed_url: ParsedURL, max_redirects: int) -> ParsedURL:
    if max_redirects <= 0:
        raise exc
    if exc.response is None:
        raise exc
    if exc.response.status not in (301, 302, 303, 307, 308):
        raise exc

    location = exc.response.headers.get("Location")

    if location is None:
        raise WSError("received redirect HTTP response without Location header",
                       exc.raw_header, exc.raw_body, exc.response) from exc

    url = urllib.parse.urljoin(old_parsed_url.url, location)
    parsed_url = parse_url(url)

    if old_parsed_url.secure and not parsed_url.secure:
        raise WSError(
            f"cannot follow redirect to non-secure URL {parsed_url.url}",
            exc.raw_header, exc.raw_body, exc.response)

    return parsed_url


def _hold_proxy_stream_until_disconnect(proxy_stream: object, ws_transport: WSTransport) -> None:
    _proxy_stream_lifecycle_guards.add(proxy_stream)

    async def _cleanup() -> None:
        try:
            await ws_transport.wait_disconnected()
        finally:
            _proxy_stream_lifecycle_guards.discard(proxy_stream)

    asyncio.get_running_loop().create_task(_cleanup())


async def ws_connect(ws_listener_factory: Callable[[], WSListener], # type: ignore [no-untyped-def]
                     url: str,
                     *,
                     ssl_context: Optional[SSLContext] = None,
                     proxy_ssl_context: Optional[SSLContext] = None,
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
    :param proxy_ssl_context: optional SSLContext to override default one when
        https proxy scheme is used
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
        ``https://`` and ``socks5://`` (including authenticated variants).
    :return: :any:`WSTransport` object and a user handler returned by `ws_listener_factory()`
    """

    assert "ssl" not in kwargs, "explicit 'ssl' argument for loop.create_connection is not supported"
    assert "sock" not in kwargs, "explicit 'sock' argument for loop.create_connection is not supported"
    assert "all_errors" not in kwargs, "explicit 'all_errors' argument for loop.create_connection is not supported"
    assert auto_ping_strategy in (WSAutoPingStrategy.PING_WHEN_IDLE, WSAutoPingStrategy.PING_PERIODICALLY), \
        "invalid value of auto_ping_strategy parameter"

    logger = getLogger(f"picows.{logger_name}")
    parsed_url = parse_url(url)

    while True:
        if parsed_url.username is not None or parsed_url.password is not None:
            logger.warning("Basic authentication was requested in URL, but it is not currently supported, ignore username and password")

        if parsed_url.secure:
            ssl_arg = ssl_context if ssl_context is not None else True
        else:
            ssl_arg = None

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
                extra_headers)

        try:
            loop = asyncio.get_running_loop()
            conn_kwargs = dict(kwargs)

            proxy_socket = None
            host = None
            port = None
            if proxy is not None:
                proxy_url = urllib.parse.urlsplit(proxy)
                proxy_scheme = proxy_url.scheme.lower()
                if proxy_scheme == "https":
                    if sys.version_info < (3, 11):
                        raise WSInvalidURL(
                            proxy,
                            "https proxy requires Python 3.11+ (asyncio StreamWriter.start_tls support)"
                        )
                    if proxy_ssl_context is None:
                        current_proxy_ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                    else:
                        current_proxy_ssl_context = proxy_ssl_context

                    if ssl_arg is None:
                        destination_ssl_context = None
                    elif isinstance(ssl_arg, SSLContext):
                        destination_ssl_context = ssl_arg
                    else:
                        destination_ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

                    http_proxy_url = urllib.parse.urlunsplit(
                        ("http", proxy_url.netloc, "", "", "")
                    )
                    stream = await ProxyV2.from_url(http_proxy_url, proxy_ssl=current_proxy_ssl_context).connect(
                        dest_host=parsed_url.host,
                        dest_port=parsed_url.port,
                        dest_ssl=destination_ssl_context)
                    ws_protocol = ws_protocol_factory()
                    stream.writer.transport.set_protocol(ws_protocol)
                    ws_protocol.connection_made(stream.writer.transport)
                    await ws_protocol.wait_until_handshake_complete()
                    _hold_proxy_stream_until_disconnect(stream, ws_protocol.transport)
                    return ws_protocol.transport, ws_protocol.listener
                else:
                    proxy_socket = await Proxy.from_url(proxy).connect(
                        dest_host=parsed_url.host,
                        dest_port=parsed_url.port)

                if ssl_arg is not None and "server_hostname" not in conn_kwargs:
                    conn_kwargs["server_hostname"] = parsed_url.host
            else:
                host = parsed_url.host
                port = parsed_url.port

            (_, ws_protocol) = await loop.create_connection(
                ws_protocol_factory, host, port, ssl=ssl_arg, sock=proxy_socket, **conn_kwargs) # type: ignore[arg-type]

            await ws_protocol.wait_until_handshake_complete()
            return ws_protocol.transport, ws_protocol.listener
        except WSError as exc:
            new_parsed_url = _maybe_handle_redirect(exc, parsed_url, max_redirects)
            logger.info("%s replied with HTTP redirect to %s, (status = %s)",
                        parsed_url.url, new_parsed_url.url, exc.response.status) # type: ignore [union-attr]
            parsed_url = new_parsed_url
            max_redirects -= 1


WSServerListenerFactory = Callable[[WSUpgradeRequest], Union[WSListener, WSUpgradeResponseWithListener, None]]


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
    :return: `asyncio.Server <https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.Server>`_ object
    """

    assert auto_ping_strategy in (WSAutoPingStrategy.PING_WHEN_IDLE, WSAutoPingStrategy.PING_PERIODICALLY), "invalid value of auto_ping_strategy parameter"

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
            None            # extra_headers
        )

    return await asyncio.get_running_loop().create_server(
        ws_protocol_factory,
        host=host,
        port=port,
        **kwargs)
