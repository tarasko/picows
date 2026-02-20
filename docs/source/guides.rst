Topic guides
===============

Making data interface async
---------------------------
The on_ws_* methods in WSListener are non-async for performance reasons.
There are several factors that make a non-async interface significantly faster than an async one:

    * Implementing an async interface requires queuing data for later processing by a coroutine, which then needs to be woken up by the event loop. This introduces a substantial delay in processing and adds extra overhead for the event loop.
    * Since data cannot be processed immediately from the read buffer, it would need to be copied, which eliminates the advantage of zero-copy.
    * Regular Cython class methods can be overloaded very efficiently (equivalent to a C function call via a vtable), which is not possible for async class methods.

In summary, you can build an async interface on top of a non-async one and accept the performance trade-off when needed.
However, if the interface is async-only, you cannot avoid this performance penalty.

If you just want to turn non-async callbacks into async, the most efficient approach is to use
`eager tasks <https://docs.python.org/3/library/asyncio-task.html#eager-task-factory>`_ available since python 3.13.
Eager tasks do not wait for the next event loop cycle and get executed immediately.
See `echo_client_async_callbacks.py <https://raw.githubusercontent.com/tarasko/picows/master/examples/echo_client_async_callbacks.py>`_
illustrating this approach.

If you need an async receive_message(), similar to what aiohttp and websockets offer, then you would have to use asyncio.Queue.
The latency penalty will become bigger, since awaiting coroutine can only be woken up on the next event loop cycle
and message payload will always have to be copied.
See `echo_client_async_iteration.py <https://raw.githubusercontent.com/tarasko/picows/master/examples/echo_client_async_iteration.py>`_
illustrating this approach.

**picows** lets you choose the best possible approach for your project. Very often turning async is not really necessary on
the data path. With **picows** you can delay this and do it only when necessary, for example, only when you actually have to start
some async operation.

Message fragmentation
---------------------
In the WebSocket protocol, there is a distinction between messages and frames.
A message can be split across multiple frames, and reassembling them is done by concatenating the frame payloads.

.. important::
    Consider verifying what the remote peer is sending.
    It's very common for clients and servers to never fragment their messages. In such case **Frame** == **Message**.
    Additionally, control messages like PING, PONG, and CLOSE are never fragmented.

**picows** does not attempt to concatenate frames automatically, as the most
efficient way to handle this may vary depending on the specific use case.

Message fragmentation works as follows:

Unfragmented message::

    WSFrame(msg_type=WSMsgType.<actual message type>, fin=True)

Fragmented message::

    WSFrame(msg_type=WSMsgType.<actual message type>, fin=False)
    WSFrame(msg_type=WSMsgType.CONTINUATION, fin=False)
    ...
    # the last frame of the message
    WSFrame(msg_type=WSMsgType.CONTINUATION, fin=True)

`echo_client_fragmented_msg.py <https://raw.githubusercontent.com/tarasko/picows/master/examples/echo_client_fragmented_msg.py>`_
demonstrates how to correctly split messages and how to assemble them back.

Enable debug logs
-----------------

**picows** logs using Python's standard logging module under picows.* logger.
You may use any available way to set log level to PICOWS_DEBUG_LL (=9) to enable
debug logging.

.. code-block:: python

    # Either set global log level
    logging.basicConfig(level=picows.PICOWS_DEBUG_LL)
    # Or set picows logger log level only
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("picows").setLevel(picows.PICOWS_DEBUG_LL)

Exceptions handling
-------------------

When talking about how the library deals with exceptions, there are two questions that
must be addressed:

**What kinds of exceptions can the library functions throw?**

**picows** may raise any exception that the underlying system calls may raise.
For example, `ConnectionResetError` from :any:`ws_connect` or `BrokenPipeError`
from :any:`WSTransport.send`.

**picows** does not wrap these exceptions in its own special exception type.
Additionally, :any:`ws_connect` may raise :any:`WSError` in cases of websocket
negotiation errors.
In general, :any:`WSError` is reserved for errors specific to websockets only.

There is also a special exception, `asyncio.CancelledError`, which any coroutine
can raise when it is externally cancelled. Sometimes you need to handle this
exception manually. For example, in a reconnection loop where you want to
reconnect on any error, the loop should break on `asyncio.CancelledError`.

**What happens if a user callback raises an exception, and how does the library handle it?**

In most cases, **picows** initiates websocket shutdown:

* sends CLOSE(INTERNAL_ERROR),
* closes the transport,
* and then calls :any:`WSTransport.wait_disconnected` waiters.

On the **client side**, the first exception raised by a user handler is
stored internally, transferred to :any:`WSTransport.wait_disconnected`,
and re-raised when `await transport.wait_disconnected()` completes.
This makes handler failures observable from your top-level coroutine.

On the **server side**, callback exceptions are logged and not re-raised via
`wait_disconnected` (there is no per-client await path on server internals).

For :any:`on_ws_frame`, this behavior is configurable via
`disconnect_on_exception` in :any:`ws_connect`/:any:`ws_create_server`:

* `disconnect_on_exception=True` (default): exception triggers disconnect, and on client side it is re-raised by `wait_disconnected`.
* `disconnect_on_exception=False`: exception is only logged, connection stays open.

Auto ping
--------------
`Available since 1.4`

The WebSocket protocol includes special frame types, WSMsgType.PING and WSMsgType.PONG, which are useful for detecting stale connections.

From the user's perspective, these frames function like regular frames and may contain payload data. When one side receives a PING frame, it must respond with a PONG frame that includes the same payload as the PING.

**picows** offers an efficient 'auto ping' mechanism to automatically send a PING to the remote peer after a specified period of inactivity and to handle and verify PONG responses. If no PONG is received, the WebSocket will be disconnected.

This behavior is controlled by three parameters passed to :any:`ws_connect` or :any:`ws_create_server`:

.. code-block:: python

    await ws_connect(...,
        enable_auto_ping=True,      # disabled by default
        auto_ping_idle_timeout=2,   # send ping after 2 seconds of inactivity
        auto_ping_reply_timeout=1   # expect pong reply within 1 second
    )



Furthermore, it is possible to customize what will be ping and pong frames.
Apart from PING/PONG message types, other common options are:

    * TEXT frames with 'ping' and 'pong' payload.
    * TEXT frames with full json payload like {"op": "ping"} and {"op": "pong"}

Customization is done by overloading :any:`WSListener` :any:`send_user_specific_ping` and :any:`is_user_specific_pong` methods.

.. code-block:: python

    class ClientListener(picows.WSListener):
        ...
        def send_user_specific_ping(transport: picows.WSTransport):
            transport.send(picows.WSMsgType.TEXT, b"ping")
            # default implementation does:
            # transport.send_ping()

        def is_user_specific_pong(frame: picows.WSFrame):
            return frame.msg_type == picows.WSMsgType.TEXT and frame.get_payload_as_memoryview() == b"pong"
            # default implementation does:
            # return frame.msg_type == picows.WSMsgType.PONG

Please note that :any:`is_user_specific_pong` is designed to be fast, as it is called for every incoming message before the :any:`on_ws_frame` invocation.
A common pitfall is parsing the payload with a JSON parser twice.
If this applies to your use case, it's better to delay the determination of a pong until after the payload has been parsed in :any:`on_ws_frame`.

.. code-block:: python

    class ClientListener(picows.WSListener):
        ...
        def send_user_specific_ping(transport: picows.WSTransport):
            transport.send(picows.WSMsgType.TEXT, b'{"op":"ping"}')

        def is_user_specific_pong(frame: picows.WSFrame):
            # It is inefficient to do json.loads(frame.get_payload_as_utf8_text()) here.
            # Because we would have to do it again in on_ws_frame
            return False

        def on_ws_frame(transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.TEXT:
                obj = json.loads(frame.get_payload_as_utf8())
                if obj["op"] == "pong":
                    # Notify transport that pong reply has been received
                    transport.notify_user_specific_pong_received()
                    return

            # Process other operations
            ...


Auto pong
---------
`Available since 1.6`

By default **picows** always replies to incoming PING messages with PONG.
This is controlled by `enable_auto_pong` argument to :any:`ws_connect`
and :any:`ws_create_server`. If disabled, PING messages must be handled
manually from :any:`on_ws_frame`.

.. code-block:: python

    class ClientListener(picows.WSListener):
        ...
        def on_ws_frame(transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.PING:
                transport.send_pong(frame.get_payload_as_bytes())

            ...

Graceful websocket shutdown
---------------------------

According to RFC 6455, graceful websocket shutdown is a CLOSE handshake:
one side sends a CLOSE frame, the peer replies with CLOSE, and then both
sides close the underlying TCP connection.

**picows** does not perform full websocket CLOSE handshake automatically:

* :any:`WSTransport.disconnect` does **not** call :any:`WSTransport.send_close`.
* Incoming CLOSE frames are delivered to :any:`WSListener.on_ws_frame`; **picows**
  does not automatically send CLOSE reply.

If you want graceful websocket shutdown, handle CLOSE explicitly in your
listener:

.. code-block:: python

    class Listener(picows.WSListener):

        def initiate_close(self, transport: picows.WSTransport):
            transport.send_close(picows.WSCloseCode.OK, b"done")
            transport.disconnect()

        def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.CLOSE:
                # If peer initiates close, echo CLOSE and then disconnect.
                # If CLOSE is a reply to our CLOSE, it safe to call send_close and disconnect again.
                # They will be ignored.
                transport.send_close(frame.get_close_code(), frame.get_close_message())
                transport.disconnect()
                return

            ...

`graceful_shutdown.py <https://raw.githubusercontent.com/tarasko/picows/master/examples/graceful_shutdown.py>`_
contains a complete runnable example.

You do not need extra guards around those calls:

* After the first :any:`WSTransport.send_close`, subsequent send calls
  (:any:`WSTransport.send`, :any:`WSTransport.send_ping`,
  :any:`WSTransport.send_pong`, :any:`WSTransport.send_close`) are no-ops.
* :any:`WSTransport.disconnect` is idempotent and safe to call multiple times.

Disconnect behavior and asyncio transport semantics
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:any:`WSTransport.send`, :any:`WSTransport.send_ping`, :any:`WSTransport.send_pong`,
and :any:`WSTransport.send_close` eventually rely on asyncio transport
`write() <https://docs.python.org/3/library/asyncio-protocol.html#asyncio.WriteTransport.write>`_,
which may buffer data.

By default, :any:`WSTransport.disconnect` calls asyncio transport
`close() <https://docs.python.org/3/library/asyncio-protocol.html#asyncio.WriteTransport.close>`_.
This attempts to flush data that has already been enqueued by previous send calls
before the socket is closed (subject to OS/kernel behavior and network conditions).

For immediate teardown, call :any:`WSTransport.disconnect` with `graceful=False`.
This maps to asyncio transport
`abort() <https://docs.python.org/3/library/asyncio-protocol.html#asyncio.WriteTransport.abort>`_
and closes the connection without waiting for buffered outgoing data.

Measuring/checking round-trip time
----------------------------------
`Available since 1.5`

**picows** allows you to conveniently measure round-trip time to a remote peer using
:any:`measure_roundtrip_time`. This is done by sending PING requests multiple
times and measuring response delay.

Check out `okx_roundtrip_time.py <https://raw.githubusercontent.com/tarasko/picows/master/examples/okx_roundtrip_time.py>`_
example of how to measure RTT to a popular OKX crypto-currency exchange and initiate
reconnect if it does not satisfy a predefined threshold.

Dealing with slow clients
-------------------------

When a server pushes messages faster than a client can consume them, the write side of
the connection eventually hits transport high watermark limits.
On the server side, per-client listeners can react to this by overriding
:any:`WSListener.pause_writing` and :any:`WSListener.resume_writing`.

This allows implementing backpressure-aware producers: pause message generation
while writing is paused and resume only when the transport drains.

`slow_client_backpressure.py <https://raw.githubusercontent.com/tarasko/picows/master/examples/slow_client_backpressure.py>`_
demonstrates how ``pause_writing``/``resume_writing`` are triggered and how to stop
the producer while the client is slow.

Using Cython interface
----------------------

**picows** classes and enums are Cython extension types.
If you are using Cython in your project, you can access picows type definitions
and some extra functionality by importing `picows.pxd <https://raw.githubusercontent.com/tarasko/picows/master/picows/picows.pxd>`_ that is installed with the library.

Check out an `echo_client_cython.pyx <https://raw.githubusercontent.com/tarasko/picows/master/examples/echo_client_cython.pyx>`_ of a simple echo client that is written in Cython.

Using proxies
-------------
`Available since 1.13`

:any:`ws_connect` supports HTTP, SOCKS4 and SOCKS5 proxies via
`python-socks <https://github.com/romis2012/python-socks>`_.
Use the ``proxy`` argument with a proxy URL. HTTPS proxy URLs (``https://...``)
are not currently supported:

.. code-block:: python

    transport, listener = await ws_connect(
        ClientListener,
        "ws://127.0.0.1:9000/",
        proxy="socks5://user:password@127.0.0.1:1080",
    )

When connecting to ``wss://`` URLs through a proxy, **picows** establishes a tunnel
through the proxy and then performs the TLS handshake with the websocket server.

Hostname resolution generally happens at the proxy, unless it is SOCK4.
SOCK4 is an old protocol, where CONNECT request doesn't support host names, only IP addresses.
SOCK4 hostname resolution is performed at the client.

Basic auth is supported. Login and password can be specified in the proxy URL.

.. _getproxies: https://docs.python.org/3/library/urllib.request.html#urllib.request.getproxies

Currently, **picows** does not attempt to use system proxy settings. If you want to use
system-wide proxy settings, get them using `getproxies`_ and pass one as the
proxy argument.

Setting socket options
----------------------

If you need custom TCP socket tuning, use :any:`on_ws_connected` callback and
adjust the raw socket there.

.. code-block:: python

    import socket
    from picows import WSListener, WSTransport

    class Listener(WSListener):
        ...
        def on_ws_connected(transport: WSTransport):
            sock: socket.socket = transport.underlying_transport.get_extra_info("socket")
            # Example: enlarge kernel socket buffers
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 * 1024 * 1024)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 * 1024 * 1024)

.. note::
    **picows** already enables `TCP_NODELAY` and, when available on the
    platform, `TCP_QUICKACK` to reduce latency by default.
