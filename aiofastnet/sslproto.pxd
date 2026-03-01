from .transport cimport Transport, Protocol
from .openssl cimport *


cpdef enum SSLProtocolState:
    UNWRAPPED = 0
    DO_HANDSHAKE = 1
    WRAPPED = 2
    FLUSHING = 3
    SHUTDOWN = 4


cdef enum AppProtocolState:
    # This tracks the state of app protocol (https://git.io/fj59P):
    #
    #     INIT -cm-> CON_MADE [-dr*->] [-er-> EOF?] -cl-> CON_LOST
    #
    # * cm: connection_made()
    # * dr: data_received()
    # * er: eof_received()
    # * cl: connection_lost()

    STATE_INIT = 0
    STATE_CON_MADE = 1
    STATE_EOF = 2
    STATE_CON_LOST = 3


cdef class SSLConnection:
    cdef:
        object ssl_ctx_py
        SSL_CTX* ssl_ctx
        BIO* incoming
        BIO* outgoing
        SSL* ssl_object
        str server_hostname

    cdef inline dict getpeercert(self)
    cdef inline tuple cipher(self)
    cdef inline str compression(self)
    cdef inline make_exc_from_ssl_error(self, str descr, int err_code)
    cdef inline _exc_from_err_last_error(self, str descr)
    cdef inline _decode_certificate(self, X509* certificate)
    cdef inline _configure_hostname(self)


cdef class SSLTransport(Transport):
    cdef:
        object _loop
        SSLProtocol _ssl_protocol
        bint _closed
        object context


cdef class SSLProtocol(Protocol):
    cdef:
        bint _server_side
        str _server_hostname
        object _sslcontext
        SSLConnection _ssl_connection

        dict _extra
        list _write_backlog

        object _loop
        SSLTransport _app_transport

        Transport _transport
        object _ssl_handshake_timeout
        object _ssl_shutdown_timeout
        object _ssl_handshake_complete_waiter

        # Buffer for the underlying TCP protocol buffered reads
        bytearray _tcp_read_buffer

        SSLProtocolState _state
        size_t _conn_lost
        AppProtocolState _app_state

        object _app_protocol
        bint _app_protocol_is_buffered

        object _handshake_start_time
        object _handshake_timeout_handle
        object _shutdown_timeout_handle

        bint _reading_paused

    # Instead of doing python calls, c methods *_impl are called directly
    # from stream.pyx

    cpdef get_app_transport(self, context=*)
    cpdef set_app_protocol(self, app_protocol)
    cpdef get_app_protocol(self)

    cdef inline Transport get_tcp_transport(self)

    # Overloads from Protocol
    cpdef is_buffered_protocol(self)
    cpdef get_buffer(self, Py_ssize_t hint)
    cpdef buffer_updated(self, Py_ssize_t bytes_read)
    cpdef get_local_write_buffer_size(self)

    cdef inline _wakeup_waiter(self, exc=*)
    cdef inline _get_extra_info(self, name, default=*)
    cdef inline _set_state(self, SSLProtocolState new_state)

    # Handshake flow

    cdef inline _start_handshake(self)
    cdef inline _check_handshake_timeout(self)
    cdef inline _do_handshake(self)
    cdef inline _on_handshake_complete(self, handshake_exc)

    # Shutdown flow

    cdef inline _start_shutdown(self, object context=*)
    cdef inline _check_shutdown_timeout(self)
    cdef inline _do_read_into_void(self, object context)
    cdef inline _do_flush(self, object context=*)
    cdef inline _do_shutdown(self, object context=*)
    cdef inline _on_shutdown_complete(self, shutdown_exc)
    cdef inline _abort(self, exc)

    # Outgoing flow

    cdef inline write(self, data)
    cdef inline writelines(self, data)
    cdef inline write_mem(self, char* ptr, Py_ssize_t sz)

    cdef inline bint _is_protocol_ready(self) except -1
    cdef inline _check_and_enqueue_appdata(self, data)
    cdef inline _flush_write_backlog(self)
    cdef inline _do_write(self)
    cdef inline _process_outgoing(self)

    # Incoming flow

    cpdef get_buffer(self, Py_ssize_t n)
    cpdef buffer_updated(self, Py_ssize_t nbytes)
    cpdef _do_read(self)
    cdef inline _do_read__buffered(self)
    cdef inline _do_read__copied(self)
    cdef inline _call_eof_received(self, object context=*)

    cdef inline pause_reading(self)
    cdef inline resume_reading(self)

    cpdef pause_writing(self)
    cpdef resume_writing(self)

    cdef inline _fatal_error(self, exc, message=*)
