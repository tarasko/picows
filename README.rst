picows is a library for building WebSocket clients and servers with a focus on performance. 

Performance
-----------
picows is implemented in Cython and thus provides unparallel performance comparing to other popular websocket libraries.


.. image:: https://raw.githubusercontent.com/tarasko/picows/master/docs/picows_benchmark.png
  :target: https://github.com/tarasko/picows/blob/master/docs/picows_benchmark.png?raw=true

The above chart shows the performance of echo clients using popular python libraries. 
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

Features
--------

