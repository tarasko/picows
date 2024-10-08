picows Release History
=================================

.. contents::
   :depth: 1
   :local:

1.4.1 (2024-10-08)

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
