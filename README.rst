picows is a library for building WebSocket clients and servers with a focus on performance. 

Performance
-----------
picows is implemented in Cython and thus provides unparallel performance comparing to other popular websocket libraries.


.. image:: https://raw.githubusercontent.com/tarasko/picows/master/docs/picows_benchmark.png
  :target: https://github.com/tarasko/picows/blob/master/docs/picows_benchmark.png?raw=true

The above chart shows the performance of echo clients communicating to a server through a loopback interface using popular python libraries. 
`boost.beast client <https://www.boost.org/doc/libs/1_85_0/libs/beast/example/websocket/client/sync/websocket_client_sync.cpp>`_
is also included for reference. Typically picows is ~ 1.5-2 times faster than aiohttp. All python clients use uvloop. Please find the benchmark sources 
`here <https://github.com/tarasko/picows/blob/master/examples/echo_client_benchmark.py>`_

Installation
------------

picows requires Python 3.8 or greater and is available on PyPI.
Use pip to install it::

    $ pip install picows

Rationale
---------
Popular websocket libraries attempt to provide high level interfaces. They take care of optional decompression, assembling websocket messages from frames, as well as implementing async iteration interface.
These features come with a significant cost even when messages are small, unfragmented (every websocket frame is final) and uncompressed. Async iteration interface is done using Futures and it is an extra work for event loop, plus it introduce delays. Furthermore it is not always possible to check if more messages have already arrived, sometimes it is only last message that matters.

Features
--------
* Maximally efficient websocket frame parser and builder implemented in cython
* Re-use memory as much as possible, avoid reallocations, avoid unnecessary python object creations
* Provide cython .pxd for efficient integration of user cythonized code with picows
* Ability to check if a frame is the last one in the receiving buffer


