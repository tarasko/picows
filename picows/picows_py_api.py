import asyncio
import urllib.parse
from ssl import SSLContext
from typing import Callable, Optional, Union

from .picows import (WSListener, WSTransport, WSHeadersLike, WSAutoPingStrategy,
                     WSProtocol,
                     WSUpgradeRequest, WSUpgradeResponseWithListener)


async def ws_connect(ws_listener_factory: Callable[[], WSListener],
                     url: str,
                     *,
                     ssl_context: Optional[SSLContext]=None,
                     disconnect_on_exception: bool=True,
                     websocket_handshake_timeout=5,
                     logger_name: str="client",
                     enable_auto_ping: bool = False,
                     auto_ping_idle_timeout: float=10,
                     auto_ping_reply_timeout: float=10,
                     auto_ping_strategy = WSAutoPingStrategy.PING_WHEN_IDLE,
                     enable_auto_pong: bool=True,
                     max_frame_size: int = 10 * 1024 * 1024,
                     extra_headers: Optional[WSHeadersLike]=None,
                     **kwargs
                     ) -> tuple[WSTransport, WSListener]:
    """
    Open a websocket connection to a given URL.

    This function forwards its `kwargs` directly to
    `asyncio.loop.create_connection <https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_connection>`_

    :param ws_listener_factory:
        A parameterless factory function that returns a user handler. User handler has to derive from :any:`WSListener`.
    :param url: Destination URL
    :param ssl_context: optional SSLContext to override default one when wss scheme is used
    :param disconnect_on_exception:
        Indicates whether the client should initiate disconnect on any exception
        thrown from WSListener.on_ws_frame callbacks
    :param websocket_handshake_timeout:
        is the time in seconds to wait for the websocket client to receive websocket handshake response before aborting the connection.
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
        If enabled then picows will automatically reply to incoming PING frames.
    :param max_frame_size:
        * Maximum allowed frame size. Disconnect will be initiated if client receives a frame that is bigger than max size.
    :param extra_headers:
        Arbitrary HTTP headers to add to the handshake request.
    :return: :any:`WSTransport` object and a user handler returned by `ws_listener_factory()`
    """

    assert "ssl" not in kwargs, "explicit 'ssl' argument for loop.create_connection is not supported"
    assert "sock" not in kwargs, "explicit 'sock' argument for loop.create_connection is not supported"
    assert "all_errors" not in kwargs, "explicit 'all_errors' argument for loop.create_connection is not supported"
    assert auto_ping_strategy in (WSAutoPingStrategy.PING_WHEN_IDLE, WSAutoPingStrategy.PING_PERIODICALLY), "invalid value of auto_ping_strategy parameter"

    url_parts = urllib.parse.urlparse(url, allow_fragments=False)

    if url_parts.scheme == "wss":
        ssl = ssl_context if ssl_context is not None else True
        port = url_parts.port or 443
    elif url_parts.scheme == "ws":
        ssl = None
        port = url_parts.port or 80
    else:
        raise ValueError(f"invalid url scheme: {url}")

    path_plus_query = url_parts.path
    if url_parts.query:
        path_plus_query += "?" + url_parts.query

    def ws_protocol_factory():
        return WSProtocol(
            url_parts.netloc,
            path_plus_query,
            True,
            ws_listener_factory,
            logger_name,
            disconnect_on_exception,
            websocket_handshake_timeout,
            enable_auto_ping,
            auto_ping_idle_timeout,
            auto_ping_reply_timeout,
            auto_ping_strategy,
            enable_auto_pong,
            max_frame_size,
            extra_headers)

    (_, ws_protocol) = await asyncio.get_running_loop().create_connection(
        ws_protocol_factory, url_parts.hostname, port, ssl=ssl, **kwargs)

    await ws_protocol.wait_until_handshake_complete()
    return ws_protocol.transport, ws_protocol.listener


WSServerListenerFactory = Callable[[WSUpgradeRequest], Union[WSListener, WSUpgradeResponseWithListener, None]]


async def ws_create_server(ws_listener_factory: WSServerListenerFactory,
                           host=None,
                           port=None,
                           *,
                           disconnect_on_exception: bool=True,
                           websocket_handshake_timeout=5,
                           logger_name: str="server",
                           enable_auto_ping: bool = False,
                           auto_ping_idle_timeout: float = 20,
                           auto_ping_reply_timeout: float = 20,
                           auto_ping_strategy = WSAutoPingStrategy.PING_WHEN_IDLE,
                           enable_auto_pong: bool = True,
                           max_frame_size: int = 10 * 1024 * 1024,
                           **kwargs
                           ) -> asyncio.Server:
    """
    Create a websocket server listening on TCP port of the host address.
    This function forwards its `kwargs` directly to
    `asyncio.loop.create_server <https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.create_server>`_

    It has a few extra parameters to control the behaviour of websocket

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
        If enabled then picows will automatically reply to incoming PING frames.
    :param max_frame_size:
        * Maximum allowed frame size. Disconnect will be initiated if server side receives frame that is bigger than max size.
    :return: `asyncio.Server <https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.Server>`_ object
    """

    assert auto_ping_strategy in (WSAutoPingStrategy.PING_WHEN_IDLE, WSAutoPingStrategy.PING_PERIODICALLY), "invalid value of auto_ping_strategy parameter"

    def ws_protocol_factory():
        return WSProtocol(
            None,           # host+port
            None,           # ws_path
            False,          # is_client_side
            ws_listener_factory,
            logger_name,
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
