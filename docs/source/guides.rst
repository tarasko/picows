Topic guides
===============

Auto ping-pong
--------------
`Available since 1.4`

The WebSocket protocol includes special frame types, WSMsgType.PING and WSMsgType.PONG, which are useful for detecting stale connections.

From the user's perspective, these frames function like regular frames and may contain payload data. When one side receives a PING frame, it must respond with a PONG frame that includes the same payload as the PING.

**picows** offers an efficient 'auto ping-pong' mechanism to automatically send a PING to the remote peer after a specified period of inactivity and to handle and verify PONG responses. If no PONG is received, the WebSocket will be disconnected.

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


Additionally, you must manually respond to incoming ``PING`` frames.
The auto-ping mechanism only handles sending ``PING`` frames to the remote peer and processing ``PONG`` replies;
it does not handle replying to incoming ``PING`` frames.

.. code-block:: python

    class ClientListener(picows.WSListener):
        ...
        def on_ws_frame(transport: picows.WSTransport, frame: picows.WSFrame):
            if frame.msg_type == picows.WSMsgType.PING:
                transport.send_pong(frame.get_payload_as_bytes())

            ...

Message fragmentation
---------------------
In the WebSocket protocol, there is a distinction between messages and frames.
A message can be split across multiple frames, and reassembling them is done by concatenating the frame payloads.

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

Here is the naive way to implement concatenation:

.. code-block:: python

    class ClientListener(picows.WSListener):
        def __init__(self):
            self._full_msg == bytearray()
            self._full_msg_type = picows.WSMsgType.TEXT

        def on_ws_frame(transport: picows.WSTransport, frame: picows.WSFrame):
            ... # Handle PING/PONG/CLOSE control frames first

            if frame.fin:
                if self._full_msg:
                    # This is the last fragment of the message because fin is set
                    # and there were previous fragments

                    assert frame.msg_type == picows.WSMsgType.CONTINUATION

                    self._full_msg += frame.get_payload_as_memoryview()
                    self.on_concatenated_message(transport, self._full_msg_type, self._full_msg)
                    self._full_msg.clear()
                else:
                    # This is the only fragment of the message because fin is set
                    # and there was not previous fragments
                    self.on_unfragmented_message(transport, frame)
            else:
                if not self._full_msg:
                    # First fragment determine the whole message type
                    self._full_msg_type == frame.msg_type

                # Accumulate payload from multiple fragments
                self._full_msg += frame.get_payload_as_memoryview()
                return

        def on_unfragmented_message(self, transport: picows.WSTransport, frame: picows.WSFrame):
            # Called for the simple case when a frame is a whole message
            pass

        def on_concatenated_message(self, msg_type: picows.WSMsgType, payload: bytearray):
            # Called after concatenating a message from multiple frames
            pass

Before blindly coping this code, consider checking what remote peer is sending.
It is very common that clients and servers never fragment their messages.
Also control messages PING/PONG/CLOSE are never fragmented.

Async iteration
---------------
The on_ws_* methods in WSListener are non-async for performance reasons.
There are several factors that make a non-async interface significantly faster than an async one:

    * Implementing an async interface requires queuing data for later processing by a coroutine, which then needs to be woken up by the event loop. This introduces a substantial delay in processing and adds extra overhead for the event loop.
    * Since data cannot be processed immediately from the read buffer, it would need to be copied, which eliminates the advantage of zero-copy.
    * Regular Cython class methods can be overloaded very efficiently (equivalent to a C function call via a vtable), which is not possible for async class methods.

In summary, you can build an async interface on top of a non-async one and accept the performance trade-off when needed.
However, if the interface is async-only, you cannot avoid this performance penalty.

Here is a one way to implement async iteration using asyncio.Queue:

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

Check out and an `example <https://raw.githubusercontent.com/tarasko/picows/master/examples/echo_client_cython.pyx>`_ of a simple echo client that is written in Cython.
