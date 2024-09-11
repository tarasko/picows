picows Release History
=================================

.. contents::
   :depth: 1
   :local:

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
