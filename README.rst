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

**picows** is a high-performance python library designed for building asyncio WebSocket clients and servers.
Implemented in Cython, it offers exceptional speed and efficiency, surpassing other popular WebSocket python libraries.

.. image:: https://raw.githubusercontent.com/tarasko/picows/master/docs/source/_static/picows_benchmark.png
    :target: https://github.com/tarasko/picows/blob/master/docs/source/_static/picows_benchmark.png?raw=true
    :align: center


The above chart shows the performance of echo clients communicating with a server through a loopback interface using popular Python libraries. 
`boost.beast client <https://www.boost.org/doc/libs/1_85_0/libs/beast/example/websocket/client/sync/websocket_client_sync.cpp>`_
is also included for reference. Typically, picows is ~1.5-2 times faster than aiohttp. All Python clients use uvloop. Please find the benchmark sources 
`here <https://github.com/tarasko/picows/blob/master/examples/echo_client_benchmark.py>`_.

Installation
============

picows requires Python 3.8 or greater and is available on PyPI.
Use pip to install it::

    $ pip install picows


Documentation
=============

https://picows.readthedocs.io/en/stable/

Motivation
==========
Popular WebSocket libraries attempt to provide high-level interfaces.
They take care of timeouts, flow control, optional compression/decompression,
assembling WebSocket messages from frames, as well as implementing async iteration interfaces.
These features are often implemented in pure Python and come with a significant
cost even when messages are small, un-fragmented (every WebSocket frame is final),
and uncompressed. The async iteration interface is done using Futures,
which adds extra work for the event loop and introduces delays.
Furthermore, it is not always possible to check if more messages have already
arrived; in some use cases, only the last message matters and other messages can be
discarded without even parsing their content.


API Design
==========
The API follows the `transport/protocol design from asyncio <https://docs.python.org/3/library/asyncio-protocol.html#asyncio-transports-protocols>`_.
The data path is non-async.
A user handler receive frames objects instead of messages.
A message can potentially consist of multiple frames but it is up to user to choose the best strategy for concatenating them.

.. include:: docs/source/getting_started.rst

Features
========
* Maximally efficient WebSocket frame parser and builder implemented in Cython
* Re-use memory as much as possible, avoid reallocations, and avoid unnecessary Python object creations
* Provide Cython .pxd for efficient integration of user Cythonized code with picows
* Ability to check if a frame is the last one in the receiving buffer
* Support both secure and unsecure protocols (ws and wss schemes)

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

    # Run specific test
    $ pytest -s -v -k test_client_handshake_timeout[uvloop-plain]

5. Run benchmark::

    $ python -m examples.echo_server
    $ python -m examples.echo_client_benchmark

6. Build docs::

    $ make -C docs clean html

