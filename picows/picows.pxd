from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t


cdef enum WSParserState:
    WAIT_UPGRADE_RESPONSE = 0
    READ_HEADER = 1
    READ_PAYLOAD_LENGTH = 2
    READ_PAYLOAD_MASK = 3
    READ_PAYLOAD = 4


cpdef enum WSMsgType:
    # websocket spec types
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    PING = 0x9
    PONG = 0xA
    CLOSE = 0x8


cpdef enum WSCloseCode:
    NO_INFO = 0
    OK = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    ABNORMAL_CLOSURE = 1006
    INVALID_TEXT = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXTENSION = 1010
    INTERNAL_ERROR = 1011
    SERVICE_RESTART = 1012
    TRY_AGAIN_LATER = 1013
    BAD_GATEWAY = 1014


cdef class MemoryBuffer:
    cdef:
        Py_ssize_t size
        Py_ssize_t capacity
        char* data

    cdef inline _reserve(self, Py_ssize_t target_size)
    cdef inline void clear(self) noexcept
    cdef inline push_back(self, uint8_t byte)
    cdef inline append(self, const char* ptr, Py_ssize_t sz)
    cdef inline resize(self, Py_ssize_t new_size)
    cdef inline add_padding(self, Py_ssize_t alignment)


cdef class WSUpgradeRequest:
    cdef:
        readonly bytes method
        readonly bytes path
        readonly bytes version
        readonly dict headers


cdef class WSFrame:
    cdef:
        char* payload_ptr
        size_t payload_size
        readonly size_t tail_size
        readonly WSMsgType msg_type
        readonly uint8_t fin
        readonly uint8_t rsv1
        readonly uint8_t last_in_buffer

    cpdef bytes get_payload_as_bytes(self)
    cpdef str get_payload_as_utf8_text(self)
    cpdef str get_payload_as_ascii_text(self)
    cpdef object get_payload_as_memoryview(self)

    cpdef WSCloseCode get_close_code(self)
    cpdef bytes get_close_message(self)


cdef class WSTransport:
    cdef:
        readonly object underlying_transport    #: asyncio.Transport
        readonly bint is_client_side
        readonly bint is_secure

        object _logger                          #: Logger
        bint _log_debug_enabled
        object _disconnected_future             #: asyncio.Future
        MemoryBuffer _write_buf
        int _socket

    cdef send_reuse_external_buffer(self, WSMsgType msg_type, char* msg_ptr, size_t msg_size, bint fin=*, bint rsv1=*)
    cpdef send(self, WSMsgType msg_type, message, bint fin=*, bint rsv1=*)
    cpdef send_ping(self, message=*)
    cpdef send_pong(self, message=*)
    cpdef send_close(self, WSCloseCode close_code=*, close_message=*)
    cpdef disconnect(self)

    cdef inline _send_http_handshake(self, bytes ws_path, bytes host_port, bytes websocket_key_b64)
    cdef inline _send_http_handshake_response(self, bytes accept_val)
    cdef inline _send_bad_request(self, str error)
    cdef inline _send_not_found(self)
    cdef inline _send_internal_server_error(self, str error)
    cdef inline _mark_disconnected(self)
    cdef inline _try_native_write_then_transport_write(self, char * ptr, Py_ssize_t sz)


cdef class WSListener:
    cpdef on_ws_connected(self, WSTransport transport)
    cpdef on_ws_frame(self, WSTransport transport, WSFrame frame)
    cpdef on_ws_disconnected(self, WSTransport transport)
    cpdef pause_writing(self)
    cpdef resume_writing(self)

