.. image:: https://raw.githubusercontent.com/tarasko/picows/master/docs/source/_static/banner.png
    :align: center

Introduction
============

.. image:: https://badge.fury.io/py/picows.svg
    :target: https://pypi.org/project/picows
    :alt: Latest PyPI package version

.. image:: https://img.shields.io/pypi/dm/picows
    :target: https://pypistats.org/packages/picows
    :alt: Downloads count

.. image:: https://readthedocs.org/projects/picows/badge/?version=latest
    :target: https://picows.readthedocs.io/en/latest/
    :alt: Latest Read The Docs

**picows** is a high-performance Python library designed for building asyncio WebSocket clients and servers.
Implemented in Cython, it offers exceptional speed and efficiency, surpassing other popular Python WebSocket libraries.

.. image:: https://raw.githubusercontent.com/tarasko/websocket-benchmark/master/results/benchmark-Linux-256.png
    :target: https://github.com/tarasko/websocket-benchmark/blob/master
    :align: center


The above chart shows the performance of echo clients communicating with a server through a loopback interface using popular Python libraries.
`boost.beast client <https://www.boost.org/library/latest/beast/>`_
is also included for reference. You can find benchmark sources and more results
`here <https://github.com/tarasko/websocket-benchmark>`_.

Installation
============

picows requires Python 3.9 or greater and is available on PyPI.
Use pip to install it::

    $ pip install picows


Getting started
===============

picows provides two APIs:

* A reimplementation of the popular
  `websockets <https://websockets.readthedocs.io/en/stable/>`_ library's
  asyncio interface.

* A low-level core API. It is more efficient than the high-level websockets API
  (lower latency, higher throughput, zero-copy), but omits a few high-level
  features that aren't always required.

websockets API
--------------

This is a drop-in replacement; you only need to change imports to transition from websockets to picows.

Certain features from websockets library are not supported yet. Check out :doc:`websockets`
for the full list.

Client
~~~~~~

.. code-block:: python

    # Import picows.websockets instead of websockets
    from picows.websockets.asyncio.client import connect
    import asyncio


    async def hello():
        async with connect("ws://localhost:8765") as websocket:
            await websocket.send("Hello world!")
            message = await websocket.recv()
            print(message)


    if __name__ == "__main__":
        asyncio.run(hello())

Server
~~~~~~

.. code-block:: python

    # Import picows.websockets instead of websockets
    from picows.websockets.asyncio.server import serve
    import asyncio


    async def echo(websocket):
        async for message in websocket:
            await websocket.send(message)


    async def main():
        async with serve(echo, "localhost", 8765) as server:
            await server.serve_forever()


    if __name__ == "__main__":
        asyncio.run(main())

Core API
--------

The Core API achieves superior performance by offering an efficient, non-async
data path, similar to the
`transport/protocol design from asyncio <https://docs.python.org/3/library/asyncio-protocol.html#asyncio-transports-protocols>`_.

The user handler receives WebSocket frame objects instead of complete messages.
Since a message can span multiple frames, it is up to the user to decide the
most effective strategy for concatenating them. Each frame object includes
additional low-level details about the current parser state, which may help to
further optimize the behavior of the user's application.

The Core API doesn't offer high-level features like permessage-deflate extension
support or an async iterator interface for reading. These features are often not
required in real-world applications, significantly slow down the data path, and
make a true zero-copy interface impossible.

Client
~~~~~~

.. code-block:: python

    import asyncio
    from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode


    class ClientListener(WSListener):
        def on_ws_connected(self, transport: WSTransport):
            transport.send(WSMsgType.TEXT, b"Hello world")

        def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
            print(f"Echo reply: {frame.get_payload_as_ascii_text()}")
            transport.send_close(WSCloseCode.OK)
            transport.disconnect()


    async def main():
        transport, client = await ws_connect(ClientListener, "ws://127.0.0.1:9001")
        await transport.wait_disconnected()


    if __name__ == "__main__":
        asyncio.run(main())

Server
~~~~~~

.. code-block:: python

    import asyncio
    from picows import ws_create_server, WSFrame, WSTransport, WSListener, WSMsgType, WSUpgradeRequest


    class ServerClientListener(WSListener):
        def on_ws_connected(self, transport: WSTransport):
            print("New client connected")

        def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
            if frame.msg_type == WSMsgType.CLOSE:
                transport.send_close(frame.get_close_code(), frame.get_close_message())
                transport.disconnect()
            else:
                transport.send(frame.msg_type, frame.get_payload_as_memoryview())


    async def main():
        def listener_factory(r: WSUpgradeRequest):
            # Routing can be implemented here by analyzing request content
            return ServerClientListener()

        server: asyncio.Server = await ws_create_server(listener_factory, "127.0.0.1", 9001)
        for s in server.sockets:
            print(f"Server started on {s.getsockname()}")

        await server.serve_forever()


    if __name__ == "__main__":
        asyncio.run(main())
