picows Release History
=================================

.. contents::
   :depth: 1
   :local:

1.12.0 (2026-02-11)
------------------

* #71: add support for HTTP redirects
* Following discussion #68 added raw_header, raw_body and response attributes to WSError exception.
* Added additional checks for URL and WSInvalidURL exception
* Some non-latency critical code has been "de-cythonized" for better debugging experience.
* WSUpgradeRequest, WSUpgradeResponse, WSUpgradeResponseWithListener moved to a pure python module
* Mark picows extension module freethreading compatible

1.11.1 (2026-02-05)
------------------

* Fix accidentally disabled -O2 optimization flag (somehow picows was still faster than any other library)

1.11.0 (2026-02-04)
------------------

* #72: fixed possible memory leak due to never deleted child loggers
* Added faster versions of _mask_payload using sse2/avx2/avx512/neon intrinsics
* Switched to using BufferedProtocol for uvloop

1.10.2 (2026-01-04)
------------------

* #65: enable 3.14 builds
* #64: allow 'HTTP/1.1 101 null' upgrade response

1.10.1 (2025-08-23)
------------------

* #57: fix plain WSTransport.send does not produce 'on_ws_disconnected' event in case of errors

1.10.0 (2025-08-23)
------------------

* Drop python 3.8 support
* Strip extensions on Linux and MacOS. Reduce package's size

1.9.0 (2025-06-05)
------------------

* #47: Added WSTransport.send_reuse_external_bytearray to allow buffer sharing with msgspec or similar libraries
* #45: Clarified WSTransport.send behaviour in the reference
* #48: Re-raise exception from wait_disconnected when it is raised by user handler
* Fixed WSTransport.send_reuse_external_buffer, it was broken for client side websockets

1.8.0 (2025-02-11)
------------------

* #37: Add an option to ws_connect/ws_create_server to increase maximum allowed frame size
* Change default value of max_frame_size to 10Mb
* Allow weak references to WSTransport objects
* Be more reliable when delivering close frames with errors sent by picows itself

1.7.2 (2024-12-13)
------------------

* #27: Type stubs are missing return type annotations
* #28: New logo, credits to @River-Shi
* Fix lint warnings, more rigorous CI checks

1.7.1 (2024-11-27)
------------------

* Added extra_headers argument to ws_connect
* Added request/response attributes to WSTransport. They can be used to access headers after successful negotiation
* listener_factory passed to ws_create_server can now return WSUpgradeResponseWithListener to customize upgrade responses

1.6.0 (2024-10-15)
------------------

* Added optional automatic replies to incoming PING messages, enabled by default
* Added auto_ping_strategy argument to ws_connect/ws_create_server that controls when pings are sent
* Added new topic guides to the documentation

1.5.0 (2024-10-10)
------------------

* Added WSTransport.measure_roundtrip_time method + example

1.4.1 (2024-10-08)
------------------

* Log disconnect due to no PONG reply on INFO level
* Make WSFrame string representation more descriptive
* Fix minor mistakes in documentation

1.4.0 (2024-10-07)
------------------

* Added optional automatic ping-pong mechanism to detect broken connection
* Added an option to WSTransport.disconnect to disconnect immediately without flushing send buffers
* Re-structured documentation, added 'Topic guides' section

1.3.0 (2024-10-01)
------------------

* Change WSUpgradeRequest.headers type from Dict to CIMultiDict
* Fix: ws_connect is ignoring URI query parameters
* Fix: WSUpgradeRequest.version field is always None

1.2.2 (2024-09-13)
------------------

* Fix: picows wasn't working on windows with asyncio and python<=3.10 because data_received callback gets bytearray object instead of bytes.
* Fix: ws_connect was throwing TimeoutError on handshake timeouts, changed to asyncio.TimeoutError just to be consistent with the rest asyncio behaviour

1.2.1 (2024-09-11)
------------------

* Optimization: Internal memory buffers were calling PyMem_Realloc too often

1.2.0 (2024-09-05)
------------------

* Optimization: use direct send syscall and forward data to underlying transport only on EWOULDBLOCK.
* Optimization: disable usage of BufferedProtocol because profiler showed that it is slower than regular data_received

1.1.1 (2024-08-30)
------------------

* Release binary wheels along with source dist


1.1.0 (2024-08-23)
------------------

* Add fin and rsv1 parameters to send and send_reuse_external_buffer methods
* Cleanup API reference


1.0.0 (2024-08-21)
------------------

**First non-beta release**
