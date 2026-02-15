Topic guides
===============

Auto ping
--------------
`Available since 1.4`

The WebSocket protocol includes special frame types, WSMsgType.PING and WSMsgType.PONG, which are useful for detecting stale connections.

From the user's perspective, these frames function like regular frames and may contain payload data. When one side receives a PING frame, it must respond with a PONG frame that includes the same payload as the PING.

**picows** offers an efficient 'auto ping' mechanism to automatically send a PING to the remote peer after a specified period of inactivity and to handle and verify PONG responses. If no PONG is received, the WebSocket will be disconnected.

This behaviour is controlled by the 3 parameters passed to :any:`ws_connect` or :any:`ws_create_server`:

.. code-block:: python

    await ws_connect(...,
        enable_auto_ping=True,      # disabled by default
        auto_ping_idle_timeout=2,   # send ping after 2 seconds of inactivity
        auto_ping_reply_timeout=1   # expect pong reply within 1 second
    )



Furthermore, it is possible to customize what will be ping and pong frames.
Apart from PING/PONG msg types other common options are:

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

Measuring/checking round-trip time
----------------------------------
`Available since 1.5`

**picows** allows to conveniently measure round-trip time to a remote peer using
:any:`measure_roundtrip_time`. This is done by sending PING request multiple
times and measuring response delay.

Checkout an `okx_roundtrip_time.py <https://raw.githubusercontent.com/tarasko/picows/master/examples/okx_roundtrip_time.py>`_
example of how to measure RTT to a popular OKX crypto-currency exchange and initiate
reconnect if it doesn't satisfy a predefined threshold.

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

If you need an async get_message(), similar to what aiohttp and websockets offer, than you would have to use asyncio.Queue.
The latency penalty will become bigger, since awaiting coroutine can only be woken up on the next event loop cycle
and message payload will always have to be copied.


.. code-block:: python

    class ClientListener(picows.WSListener):
        def __init__(self):
            self.msg_queue = asyncio.Queue()

        ...
        def on_ws_frame(transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.TEXT:
                obj = json.loads(frame.get_payload_as_utf8_text())
                self.msg_queue.put_nowait(obj)

        def on_ws_disconnected(transport: picows.WSTransport):
            # Push None to indicate the end of the stream
            self.msg_queue.put_nowait(None)


    async def some_async_function():
        transport, listener = await ws_connect(ClientListener, ...)
        while True:
            msg = await listener.msg_queue.get()
            listener.msg_queue.task_done()
            if msg is None:
                # client disconnected
            :else
                # Otherwise process message in async context

Another approach would be to just use asyncio.Loop.create_task:

.. code-block:: python

    async def process_message(msg):
        ...

    class ClientListener(picows.WSListener):
        def on_ws_frame(transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.TEXT:
                msg = json.loads(frame.get_payload_as_utf8_text())
                asyncio.get_running_loop().create_task(process_message(msg))

Consider using it together with `eager task factory <https://docs.python.org/3/library/asyncio-task.html#eager-task-factory>`_.

Using Cython interface
----------------------

**picows** classes and enums are Cython extension types.
If you are using Cython in your project, you can access picows type definitions
and some extra functionality by importing `picows.pxd <https://raw.githubusercontent.com/tarasko/picows/master/picows/picows.pxd>`_ that is installed with the library.

Check out an `echo_client_cython.pyx <https://raw.githubusercontent.com/tarasko/picows/master/examples/echo_client_cython.pyx>`_ of a simple echo client that is written in Cython.

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

When talking about how library deals with exceptions, there are 2 questions that
must be addressed:

**What kinds of exceptions can the library functions throws?**

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

This is described in the documentation of each particular method.
In most cases, **picows** will send a CLOSE frame with an INTERNAL_ERROR close code and disconnect.
However, for :any:`on_ws_frame`, it is possible to override it by setting disconnect_on_error=False
in :any:`ws_connect`/:any:`ws_create_server`.

Using proxies
-------------
`Available since 1.13`

:any:`ws_connect` supports HTTP, SOCKS4 and SOCKS5 proxies via
`python-socks <https://github.com/romis2012/python-socks>`_.
Use ``proxy`` argument with a proxy URL. HTTPS proxy URLs (``https://...``)
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

Basic auth is supported. Login/password can be specified in proxy url.

.. _getproxies: https://docs.python.org/3/library/urllib.request.html#urllib.request.getproxies

Currently **picows** doesn't attempt to use system proxy settings. If you want to use
a system wide proxy settings, get them using `getproxies`_ and pass one as a
proxy argument.
