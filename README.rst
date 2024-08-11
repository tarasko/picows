picows is a library for building WebSocket clients and servers with a focus on performance.

Performance
-----------
picows is implemented in Cython and thus provides unparalleled performance compared to other popular WebSocket libraries.

.. image:: https://raw.githubusercontent.com/tarasko/picows/master/docs/picows_benchmark.png
  :target: https://github.com/tarasko/picows/blob/master/docs/picows_benchmark.png?raw=true

The above chart shows the performance of echo clients communicating with a server through a loopback interface using popular Python libraries. 
`boost.beast client <https://www.boost.org/doc/libs/1_85_0/libs/beast/example/websocket/client/sync/websocket_client_sync.cpp>`_
is also included for reference. Typically, picows is ~1.5-2 times faster than aiohttp. All Python clients use uvloop. Please find the benchmark sources 
`here <https://github.com/tarasko/picows/blob/master/examples/echo_client_benchmark.py>`_.

Installation
------------

picows requires Python 3.8 or greater and is available on PyPI.
Use pip to install it::

    $ pip install picows

Rationale
---------
Popular WebSocket libraries attempt to provide high-level interfaces. They take care of optional decompression, assembling WebSocket messages from frames, as well as implementing async iteration interfaces.
These features come with a significant cost even when messages are small, unfragmented (every WebSocket frame is final), and uncompressed. The async iteration interface is done using Futures, which adds extra work for the event loop and introduces delays. Furthermore, it is not always possible to check if more messages have already arrived; sometimes, only the last message matters.

Features
--------
* Maximally efficient WebSocket frame parser and builder implemented in Cython
* Re-use memory as much as possible, avoid reallocations, and avoid unnecessary Python object creations
* Provide Cython .pxd for efficient integration of user Cythonized code with picows
* Ability to check if a frame is the last one in the receiving buffer
