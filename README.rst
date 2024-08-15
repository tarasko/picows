Introduction
============

.. image:: https://github.com/tarasko/picows/workflows/run%20tests/badge.svg
   :target: https://github.com/tarasko/picows/actions?query=workflow%3Arun-tests
   :alt: GitHub Actions status for master branch

.. image:: https://badge.fury.io/py/picows.svg
   :target: https://pypi.org/project/picows
   :alt: Latest PyPI package version

.. image:: https://img.shields.io/pypi/dm/picows
   :target: https://pypistats.org/packages/picows
   :alt: Downloads count

.. image:: https://readthedocs.org/projects/picows/badge/?version=latest
   :target: https://picows.readthedocs.io/en/latest/
   :alt: Latest Read The Docs

picows is a library for building WebSocket clients and servers with a focus on performance.

picows is implemented in Cython and provides unparalleled performance compared to other popular WebSocket libraries.

.. image:: https://raw.githubusercontent.com/tarasko/picows/master/docs/source/_static/picows_benchmark.png
  :target: https://github.com/tarasko/picows/blob/master/docs/source/_static/picows_benchmark.png?raw=true

The above chart shows the performance of echo clients communicating with a server through a loopback interface using popular Python libraries. 
`boost.beast client <https://www.boost.org/doc/libs/1_85_0/libs/beast/example/websocket/client/sync/websocket_client_sync.cpp>`_
is also included for reference. Typically, picows is ~1.5-2 times faster than aiohttp. All Python clients use uvloop. Please find the benchmark sources 
`here <https://github.com/tarasko/picows/blob/master/examples/echo_client_benchmark.py>`_.

Installation
============

picows requires Python 3.8 or greater and is available on PyPI.
Use pip to install it::

    $ pip install picows

Rationale
=========
Popular WebSocket libraries attempt to provide high-level interfaces. They take care of timeouts, flow control, optional compression/decompression, assembling WebSocket messages from frames, as well as implementing async iteration interfaces.
These features come with a significant cost even when messages are small, unfragmented (every WebSocket frame is final), and uncompressed. The async iteration interface is done using Futures, which adds extra work for the event loop and introduces delays. Furthermore, it is not always possible to check if more messages have already arrived; sometimes, only the last message matters.

API Design
==========
The API follows the low-level `transport/protocol design from asyncio <https://docs.python.org/3/library/asyncio-protocol.html#asyncio-transports-protocols>`_.
It passes frames instead of messages to a user handler. A message can potentially consist of multiple frames but it is up to user to choose the best strategy for merging them. 
Same principle applies for compression and flow control. User can implement their own strategies using the most appropriate tools.

That being said that the most common use-case is when messages and frames are the same, i.e. a message consists of only a single frame, and no compression is being used.

Getting started
===============

Echo client
-----------
Connects to an echo server, sends a message and disconnect upon reply.

.. code-block:: python

  import asyncio
  import uvloop
  from picows import WSFrame, WSTransport, WSListener, ws_connect, WSMsgType

  class ClientListener(WSListener):
      def on_ws_connected(self, transport: WSTransport):
          self.transport = transport
          transport.send(WSMsgType.TEXT, b"Hello world")
  
      def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
          print(f"Echo reply: {frame.get_payload_as_ascii_text()}")
          transport.disconnect()


  async def main(endpoint):
    (_, client) = await ws_connect(endpoint, ClientListener, "client")
    await client.transport.wait_until_closed()


  if __name__ == '__main__':
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    asyncio.run(main("ws://127.0.0.1:9001"))

This prints:

.. code-block::

  Echo reply: Hello world

Echo server
-----------

.. code-block:: python

  import asyncio
  import uvloop
  from picows import WSFrame, WSTransport, WSListener, ws_create_server, WSMsgType

  class ServerClientListener(WSListener):
      def on_ws_connected(self, transport: WSTransport):
          print("New client connected")
  
      def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
          transport.send(frame.msg_type, frame.get_payload_as_bytes())
          if frame.msg_type == WSMsgType.CLOSE:
              transport.disconnect()

  async def main():
      url = "ws://127.0.0.1:9001"
      server = await ws_create_server(url, ServerClientListener, "server")
      print(f"Server started on {url}")
      await server.serve_forever()

  if __name__ == '__main__':
      asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
      asyncio.run(main())


Features
========
* Maximally efficient WebSocket frame parser and builder implemented in Cython
* Re-use memory as much as possible, avoid reallocations, and avoid unnecessary Python object creations
* Provide Cython .pxd for efficient integration of user Cythonized code with picows
* Ability to check if a frame is the last one in the receiving buffer
* Support both secure and unsecure protocols (ws and wss schemes)

Documentation
=============

https://picows.readthedocs.io/