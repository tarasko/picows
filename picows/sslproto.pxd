import asyncio

cdef enum SSLProtocolState:
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


cdef class SSLTransport:
    cdef:
        object _loop
        SSLProtocol _ssl_protocol
        bint _closed
        object context


cdef class SSLProtocolBase:
    pass


cdef class SSLProtocol(SSLProtocolBase):
    cdef:
        bint _server_side
        str _server_hostname
        object _sslcontext

        object _extra

        list _write_backlog
        Py_ssize_t _write_buffer_size

        object _loop
        SSLTransport _app_transport

        object _transport
        object _ssl_handshake_timeout
        object _ssl_shutdown_timeout

        object _sslobj
        object _sslobj_read
        object _sslobj_write
        object _sslobj_pending
        object _incoming
        object _incoming_write
        object _outgoing
        object _outgoing_read

        # Buffer for the underlying UVStream buffered reads
        bytearray _tcp_read_buffer
        # Buffer for SSLObject.read calls
        # Only allocated when user pass non-buffered Protocol instance
        bytearray _ssl_read_buffer
        # Cached long object for SSLObject.read calls
        object _ssl_read_max_size_obj

        SSLProtocolState _state
        size_t _conn_lost
        AppProtocolState _app_state

        bint _ssl_writing_paused
        bint _app_reading_paused

        Py_ssize_t _incoming_high_water
        Py_ssize_t _incoming_low_water
        bint _ssl_reading_paused

        bint _app_writing_paused
        Py_ssize_t _outgoing_high_water
        Py_ssize_t _outgoing_low_water

        object _app_protocol
        bint _app_protocol_is_buffer
        object _app_protocol_get_buffer
        object _app_protocol_buffer_updated
        object _app_protocol_data_received

        object _handshake_start_time
        object _handshake_timeout_handle
        object _shutdown_timeout_handle

        readonly object ssl_handshake_complete_fut

    # Instead of doing python calls, c methods *_impl are called directly
    # from stream.pyx

    cpdef set_app_protocol(self, app_protocol)
    cpdef get_app_protocol(self)

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

    cdef inline bint _is_protocol_ready(self) except -1
    cdef inline _check_and_enqueue_appdata(self, data)
    cdef inline _flush_write_backlog(self, object context)
    cdef inline _do_write(self)
    cdef inline _process_outgoing(self)

    # Incoming flow

    cpdef _do_read(self)
    cdef inline _do_read__buffered(self)
    cdef inline _do_read__copied(self)
    cdef inline _call_eof_received(self, object context=*)

    # Flow control for writes from APP socket

    cdef inline _control_app_writing(self, object context=*)
    cdef inline Py_ssize_t _get_write_buffer_size(self)
    cdef inline _set_write_buffer_limits(self, high=*, low=*)

    # Flow control for reads to APP socket

    cdef inline _pause_reading(self)
    cdef inline _resume_reading(self, object context)

    # Flow control for reads from SSL socket

    cdef inline _control_ssl_reading(self)
    cdef inline _set_read_buffer_limits(self, high=*, low=*)
    cdef inline Py_ssize_t _get_read_buffer_size(self)
    cdef inline _fatal_error(self, exc, message=*)
