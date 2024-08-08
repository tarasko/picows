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

    cdef _reserve_if_necessary(self, Py_ssize_t bytes_to_append)
    cdef clear(self)
    cdef push_back(self, uint8_t byte)
    cdef append(self, const char* ptr, Py_ssize_t sz)
    cdef reserve(self, Py_ssize_t new_capacity)
    cdef resize(self, Py_ssize_t new_size)


cdef class WSFrame:
    cdef:
        char* payload_ptr
        size_t payload_size
        size_t tail_size
        readonly WSMsgType opcode
        readonly uint8_t fin
        readonly uint8_t last_in_buffer

    # Creates a new python object every time
    cpdef bytes get_payload_as_bytes(self)
    cpdef str get_payload_as_ascii_text(self)
    cpdef object get_payload_as_memoryview(self)

    cpdef WSCloseCode get_close_code(self)
    cpdef bytes get_close_message(self)


cdef class WSFrameParser:
    cdef:
        bytes websocket_key_b64
        object handshake_complete_future

        object _logger

        bint _log_debug_enabled
        WSParserState _state
        MemoryBuffer _buffer

        # The following are the parts of an unfinished frame
        # Once the frame is finished WSFrame is created and returned
        size_t _f_new_data_start_pos
        size_t _f_curr_state_start_pos
        size_t _f_curr_frame_start_pos
        uint64_t _f_payload_length
        size_t _f_payload_start_pos
        WSMsgType _f_opcode
        uint32_t _f_mask
        uint8_t _f_fin
        uint8_t _f_has_mask
        uint8_t _f_payload_length_flag

    cdef object get_buffer(self, size_t size_hint)
    cdef buffer_updated(self, size_t nbytes)
    cdef feed_data(self, bytes data)
    cdef shrink_buffer(self)

    cdef WSFrame get_next_frame(self)
    cdef _handle_upgrade_response(self)
    cdef bytes read_upgrade_request(self)


cdef class WSFrameBuilder:
    cdef:
        MemoryBuffer _write_buf
        bint is_client_side

    cdef prepare_frame_in_external_buffer(self, WSMsgType opcode, uint8_t* msg_ptr, size_t msg_length)
    cpdef prepare_frame(self, WSMsgType opcode, message)


cdef class WSTransport:
    cdef:
        object _transport                       #: Optional[asyncio.Transport]
        object _logger                          #: Logger
        object _disconnected_future
        WSFrameBuilder _frame_builder

    # Don't copy message, reuse its memory and append websocket header in front of the message
    # Message's buffer should have at least 10 bytes in front of the message pointer available for writing
    cdef send_reuse_external_buffer(self, WSMsgType opcode, char* message, size_t message_size)
    cpdef send(self, WSMsgType opcode, message)
    cpdef ping(self, message=*)
    cpdef pong(self, message=*)
    cpdef disconnect(self, close_message=*)

    cdef send_http_handshake(self, bytes ws_path, bytes host_port, bytes websocket_key_b64)
    cdef send_http_handshake_response(self, bytes accept_val)
    cdef mark_disconnected(self)


cdef class WSListener:
    cpdef on_ws_connected(self, WSTransport transport)
    cpdef on_ws_frame(self, WSTransport transport, WSFrame frame)
    cpdef on_ws_disconnected(self, WSTransport transport)
    cpdef pause_writing(self)
    cpdef resume_writing(self)

