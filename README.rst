.. image:: https://raw.githubusercontent.com/tarasko/picows/master/docs/source/_static/banner.png
    :align: center

Introduction
============
.. image:: https://img.shields.io/github/actions/workflow/status/tarasko/picows/run-tests.yml?branch=master
    :target: https://github.com/tarasko/picows/actions/workflows/run-tests.yml?query=branch%3Amaster

.. image:: https://badge.fury.io/py/picows.svg
    :target: https://pypi.org/project/picows
    :alt: Latest PyPI package version

.. image:: https://img.shields.io/pypi/dm/picows
    :target: https://pypistats.org/packages/picows
    :alt: Downloads count

.. image:: https://readthedocs.org/projects/picows/badge/?version=latest
    :target: https://picows.readthedocs.io/en/latest/
    :alt: Latest Read The Docs

**picows** is a high-performance python library designed for building asyncio WebSocket clients and servers.
Implemented in Cython, it offers exceptional speed and efficiency, surpassing other popular WebSocket python libraries.

.. image:: https://raw.githubusercontent.com/tarasko/picows/master/docs/source/_static/picows_benchmark.png
    :target: https://github.com/tarasko/picows/blob/master/docs/source/_static/picows_benchmark.png?raw=true
    :align: center


The above chart shows the performance of echo clients communicating with a server through a loopback interface using popular Python libraries. 
`boost.beast client <https://www.boost.org/doc/libs/1_85_0/libs/beast/example/websocket/client/sync/websocket_client_sync.cpp>`_
is also included for reference. All Python clients use uvloop. Please find the benchmark sources
`here <https://github.com/tarasko/picows/blob/master/examples/benchmark.py>`_.

Installation
============

picows requires Python 3.9 or greater and is available on PyPI.
Use pip to install it::

    $ pip install picows


Documentation
=============

https://picows.readthedocs.io/en/stable/

Motivation
==========
Popular WebSocket libraries provide high-level interfaces that handle timeouts,
flow control, optional compression/decompression, and reassembly of WebSocket messages
from frames, while also implementing async iteration interfaces.
However, these features are typically implemented in pure Python, resulting in
significant overhead even when messages are small, un-fragmented (with every WebSocket frame marked as final),
and uncompressed.

The async iteration interface relies on ``asyncio.Futures``, which adds additional
work for the event loop and can introduce delays. Moreover, it’s not always necessary
to process every message. In some use cases, only the latest message matters,
and previous ones can be discarded without even parsing their content.

API Design
==========
The library achieves superior performance by offering an efficient, non-async data path, similar to the
`transport/protocol design from asyncio <https://docs.python.org/3/library/asyncio-protocol.html#asyncio-transports-protocols>`_.
The user handler receives WebSocket frame objects instead of complete messages.
Since a message can span multiple frames, it is up to the user to decide the most
effective strategy for concatenating them. Each frame object includes additional
details about the current parser state, which may help optimize the behavior of the user’s application.

Getting started
===============

Echo client
-----------
Connects to an echo server, sends a message and disconnect upon reply.

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


    async def main(url):
        transport, client = await ws_connect(ClientListener, url)
        await transport.wait_disconnected()


    if __name__ == '__main__':
        asyncio.run(main("ws://127.0.0.1:9001"))

This prints:

.. code-block::

    Echo reply: Hello world

Echo server
-----------

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
                transport.send(frame.msg_type, frame.get_payload_as_bytes())

    async def main():
        def listener_factory(r: WSUpgradeRequest):
            # Routing can be implemented here by analyzing request content
            return ServerClientListener()

        server: asyncio.Server = await ws_create_server(listener_factory, "127.0.0.1", 9001)
        for s in server.sockets:
            print(f"Server started on {s.getsockname()}")

        await server.serve_forever()

    if __name__ == '__main__':
      asyncio.run(main())


Features
====================
* Maximally efficient WebSocket frame parser and builder implemented in Cython
* Re-use memory as much as possible, avoid reallocations, and avoid unnecessary Python object creations
* Provide Cython .pxd for efficient integration of user Cythonized code with picows
* Ability to check if a frame is the last one in the receiving buffer
* Auto ping-pong with an option to customize ping/pong messages.
* Convenient method to measure websocket roundtrip time using ping/pong messages.

Contributing / Building From Source
===================================
1. Fork and clone the repository::

    $ git clone git@github.com:tarasko/picows.git
    $ cd picows

2. Create a virtual environment and activate it::

    $ python3 -m venv picows-dev
    $ source picows-dev/bin/activate


3. Install development dependencies::

    # To run tests
    $ pip install -r requirements-test.txt

    # To run benchmark
    $ pip install -r requirements-benchmark.txt

    # To build docs
    $ pip install -r docs/requirements.txt

4. Build inplace and run tests::

    $ export PICOWS_BUILD_EXAMPLES=1
    $ python setup.py build_ext --inplace
    $ pytest -s -v

    # Run specific test with picows debug logs enabled
    $ pytest -s -v -k test_client_handshake_timeout[uvloop-plain] --log-cli-level 9

5. Run benchmark::

    $ python -m examples.echo_server
    $ python -m examples.benchmark

6. Build docs::

    $ make -C docs clean html

