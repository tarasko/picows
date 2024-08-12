import asyncio
import base64
import binascii
import hashlib
import logging
import os
import socket
import urllib.parse
from typing import cast

cimport cython

from cpython.bytes cimport PyBytes_GET_SIZE, PyBytes_AS_STRING, PyBytes_FromStringAndSize, PyBytes_CheckExact
from cpython.memoryview cimport PyMemoryView_FromMemory
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free
from cpython.buffer cimport PyBUF_WRITE, PyBUF_READ, PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.object cimport PyObject
from cpython.ref cimport Py_DECREF

from libc.string cimport memmove, memcpy
from libc.stdlib cimport rand

PICOWS_DEBUG_LL = 9


cdef extern from "arpa/inet.h" nogil:
    uint32_t ntohl(uint32_t)
    uint32_t htonl(uint32_t)
    uint16_t ntohs(uint16_t)
    uint16_t htons(uint16_t)


cdef extern from "endian.h" nogil:
    # Network order is big-endian
    uint64_t be64toh(uint64_t)
    uint64_t htobe64(uint64_t)


cdef extern from "Python.h":
    PyObject *PyUnicode_FromStringAndSize(const char *u, Py_ssize_t size)


class PicowsError(Exception):
    """WebSocket protocol parser error."""

    def __init__(self, WSCloseCode code, str message) -> None:
        self.code = code
        super().__init__(code, message)

    def __str__(self) -> str:
        return cast(str, self.args[1])


cdef _mask_payload(uint8_t* input, size_t input_len, uint32_t mask):
    cdef:
        size_t i
        # bit operations on signed integers are implementation-specific
        uint64_t mask64 = (<uint64_t>mask << 32) | <uint64_t>mask
        uint8_t* mask_buf = <uint8_t*> &mask64

    # TODO: Does input alignment impact performance here?

    if sizeof(size_t) >= 8:
        while input_len >= 8:
            (<uint64_t *> input)[0] ^= mask64
            input += 8
            input_len -= 8

    while input_len >= 4:
        (<uint32_t *> input)[0] ^= mask
        input += 4
        input_len -= 4

    for i in range(0, input_len):
        input[i] ^= mask_buf[i]


@cython.no_gc
@cython.freelist(64)
cdef class WSFrame:
    cpdef bytes get_payload_as_bytes(self):
        return PyBytes_FromStringAndSize(self.payload_ptr, <Py_ssize_t>self.payload_size)

    cpdef str get_payload_as_ascii_text(self):
        # Workaround for broken cython reference counting
        cdef str s = <str> PyUnicode_FromStringAndSize(self.payload_ptr, <Py_ssize_t>self.payload_size)
        Py_DECREF(s)
        return s

    cpdef object get_payload_as_memoryview(self):
        return PyMemoryView_FromMemory(self.payload_ptr, <Py_ssize_t>self.payload_size, PyBUF_READ)

    cpdef WSCloseCode get_close_code(self):
        if self.payload_size < 2:
            return WSCloseCode.NO_INFO
        else:
            return <WSCloseCode>ntohs((<uint16_t *>self.payload_ptr)[0])

    cpdef bytes get_close_message(self):
        if self.payload_size <= 2:
            return None
        else:
            return PyBytes_FromStringAndSize(self.payload_ptr + 2, <Py_ssize_t>self.payload_size - 2)

    def __str__(self):
        return (f"WSFrame({WSMsgType(self.opcode).name}, fin={True if self.fin else False}, "
                f"lib={True if self.last_in_buffer else False}, psz={self.payload_size}, tsz={self.tail_size})")


cdef:
    set ALLOWED_CLOSE_CODES = {int(i) for i in WSCloseCode}
    bytes _WS_DEFLATE_TRAILING = bytes([0x00, 0x00, 0xFF, 0xFF])
    bytes _WS_KEY = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


cdef class MemoryBuffer:
    def __init__(self, Py_ssize_t default_capacity=2048):
        self.size = 0
        self.capacity = default_capacity
        self.data = <char*>PyMem_Malloc(self.capacity)
        if self.data == NULL:
            raise MemoryError("cannot allocate memory for picows")

    def __dealloc__(self):
        if self.data != NULL:
            PyMem_Free(self.data)

    cdef _reserve_if_necessary(self, Py_ssize_t bytes_to_append):
        if self.size + bytes_to_append > self.capacity:
            self.reserve(256 * ((self.size + bytes_to_append) / 256 + 1))

    cdef clear(self):
        self.size = 0

    cdef push_back(self, uint8_t byte):
        self._reserve_if_necessary(1)
        self.data[self.size] = <char>byte
        self.size += 1

    cdef append(self, const char* ptr, Py_ssize_t sz):
        self._reserve_if_necessary(sz)
        memcpy(self.data + self.size, ptr, sz)
        self.size += sz

    cdef reserve(self, Py_ssize_t new_capacity):
        if new_capacity <= self.capacity:
            return
        cdef char* data = <char*>PyMem_Realloc(self.data, new_capacity)
        if data == NULL:
            raise MemoryError("cannot allocate memory for picows")
        self.data = data

    cdef resize(self, Py_ssize_t new_size):
        if new_size > self.capacity:
            self.reserve(new_size)
        self.size = new_size


cdef class WSFrameParser:
    def __init__(self, logger):
        self.websocket_key_b64 = base64.b64encode(os.urandom(16))
        self.handshake_complete_future = asyncio.get_running_loop().create_future()

        self._logger = logger

        self._log_debug_enabled = self._logger.isEnabledFor(PICOWS_DEBUG_LL)
        self._state = WSParserState.WAIT_UPGRADE_RESPONSE
        self._buffer = MemoryBuffer()

        self._f_new_data_start_pos = 0
        self._f_curr_state_start_pos = 0
        self._f_curr_frame_start_pos = 0
        self._f_payload_length = 0
        self._f_payload_start_pos = 0
        self._f_opcode = WSMsgType.CLOSE
        self._f_mask = 0
        self._f_fin = 0
        self._f_has_mask = 0
        self._f_payload_length_flag = 0

    cdef get_buffer(self, size_t size_hint):
        cdef sz = size_hint + 1024
        if self._buffer.size - self._f_new_data_start_pos < sz:
            self._buffer.resize(self._f_new_data_start_pos + sz)

        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "get_buffer(%d), provide=%d, total=%d, cap=%d",
                             size_hint,
                             self._buffer.size - self._f_new_data_start_pos,
                             self._buffer.size,
                             self._buffer.capacity)

        return PyMemoryView_FromMemory(
            self._buffer.data + self._f_new_data_start_pos,
            self._buffer.size - self._f_new_data_start_pos,
            PyBUF_WRITE)

    cdef buffer_updated(self, size_t nbytes):
        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "buffer_updated(%d), write_pos %d -> %d", nbytes,
                             self._f_new_data_start_pos, self._f_new_data_start_pos + nbytes)
        self._f_new_data_start_pos += nbytes

    cdef feed_data(self, bytes data):
        cdef:
            const char* ptr = PyBytes_AS_STRING(data)
            size_t sz = PyBytes_GET_SIZE(data)

        # Leave some space for simd parsers like simdjson, they required extra space beyond normal data to make sure
        # that vector reads don't cause access violation
        if self._buffer.size - self._f_new_data_start_pos < (sz + 64):
            self._buffer.resize(self._f_new_data_start_pos + sz + 64)

        memcpy(self._buffer.data + self._f_new_data_start_pos, ptr, sz)
        self._f_new_data_start_pos += sz

    cdef shrink_buffer(self):
        if self._f_curr_frame_start_pos > 0:
            memmove(self._buffer.data,
                    self._buffer.data + self._f_curr_frame_start_pos,
                    self._f_new_data_start_pos - self._f_curr_frame_start_pos)

            self._f_new_data_start_pos -= self._f_curr_frame_start_pos
            self._f_curr_state_start_pos -= self._f_curr_frame_start_pos
            self._f_payload_start_pos -= self._f_curr_frame_start_pos
            self._f_curr_frame_start_pos = 0

    cdef WSFrame get_next_frame(self): #  -> Optional[WSFrame]
        """Return the next frame from the socket."""
        cdef:
            uint8_t first_byte
            uint8_t second_byte
            uint8_t rsv1, rsv2, rsv3
            WSFrame frame

        if self._state == WSParserState.WAIT_UPGRADE_RESPONSE:
            self._handle_upgrade_response()
            if self._state == WSParserState.WAIT_UPGRADE_RESPONSE:
                return None

        if self._state == WSParserState.READ_HEADER:
            if self._f_new_data_start_pos - self._f_curr_state_start_pos < 2:
                return None

            first_byte = <uint8_t>self._buffer.data[self._f_curr_state_start_pos]
            second_byte = <uint8_t>self._buffer.data[self._f_curr_state_start_pos + 1]

            self._f_fin = (first_byte >> 7) & 1
            rsv1 = (first_byte >> 6) & 1
            rsv2 = (first_byte >> 5) & 1
            rsv3 = (first_byte >> 4) & 1
            self._f_opcode = <WSMsgType>(first_byte & 0xF)

            # frame-fin = %x0 ; more frames of this message follow
            #           / %x1 ; final frame of this message
            # frame-rsv1 = %x0 ;
            #    1 bit, MUST be 0 unless negotiated otherwise
            # frame-rsv2 = %x0 ;
            #    1 bit, MUST be 0 unless negotiated otherwise
            # frame-rsv3 = %x0 ;
            #    1 bit, MUST be 0 unless negotiated otherwise
            #
            # Remove rsv1 from this test for deflate development
            if rsv1 or rsv2 or rsv3:
                mem_dump = PyBytes_FromStringAndSize(
                    self._buffer.data + self._f_curr_state_start_pos,
                    max(self._f_new_data_start_pos - self._f_curr_state_start_pos, 64)
                )
                raise PicowsError(
                    WSCloseCode.PROTOCOL_ERROR,
                    f"Received frame with non-zero reserved bits, rsv1={rsv1}, rsv2={rsv2}, rsv3={rsv3}, opcode={self._f_opcode}: {mem_dump}",
                )

            if self._f_opcode > 0x7 and not self._f_fin:
                raise PicowsError(
                    WSCloseCode.PROTOCOL_ERROR,
                    "Received fragmented control frame",
                )

            self._f_has_mask = (second_byte >> 7) & 1
            self._f_payload_length_flag = second_byte & 0x7F

            # Control frames MUST have a payload
            # length of 125 bytes or less
            if self._f_opcode > 0x7 and self._f_payload_length_flag > 125:
                raise PicowsError(
                    WSCloseCode.PROTOCOL_ERROR,
                    "Control frame payload cannot be " "larger than 125 bytes",
                )

            self._f_curr_state_start_pos += 2
            self._state = WSParserState.READ_PAYLOAD_LENGTH

        # read payload length
        if self._state == WSParserState.READ_PAYLOAD_LENGTH:
            if self._f_payload_length_flag == 126:
                if self._f_new_data_start_pos - self._f_curr_state_start_pos < 2:
                    return None
                self._f_payload_length = ntohs((<uint16_t*>&self._buffer.data[self._f_curr_state_start_pos])[0])
                self._f_curr_state_start_pos += 2
            elif self._f_payload_length_flag > 126:
                if self._f_new_data_start_pos - self._f_curr_state_start_pos < 8:
                    return None
                self._f_payload_length = be64toh((<uint64_t*>&self._buffer.data[self._f_curr_state_start_pos])[0])
                self._f_curr_state_start_pos += 8
            else:
                self._f_payload_length = self._f_payload_length_flag

            if self._f_has_mask:
                self._state = WSParserState.READ_PAYLOAD_MASK
            else:
                self._f_payload_start_pos = self._f_curr_state_start_pos
                self._state = WSParserState.READ_PAYLOAD

        # read payload mask
        if self._state == WSParserState.READ_PAYLOAD_MASK:
            if self._f_new_data_start_pos - self._f_curr_state_start_pos < 4:
                return None

            self._f_mask = (<uint32_t*>&self._buffer.data[self._f_curr_state_start_pos])[0]
            self._f_curr_state_start_pos += 4
            self._f_payload_start_pos = self._f_curr_state_start_pos
            self._state = WSParserState.READ_PAYLOAD

        if self._state == WSParserState.READ_PAYLOAD:
            # Check if we have not yet received the whole payload
            if self._f_new_data_start_pos - self._f_payload_start_pos < self._f_payload_length:
                return None

            if self._f_has_mask:
                _mask_payload(<uint8_t*>self._buffer.data + self._f_payload_start_pos,
                              self._f_payload_length,
                              self._f_mask)

            frame = <WSFrame>WSFrame.__new__(WSFrame)
            frame.payload_ptr = self._buffer.data + self._f_payload_start_pos
            frame.payload_size = self._f_payload_length
            frame.tail_size = self._f_new_data_start_pos - (self._f_curr_state_start_pos + self._f_payload_length)
            frame.opcode = self._f_opcode
            frame.fin = self._f_fin
            frame.last_in_buffer = 0

            self._f_curr_state_start_pos += self._f_payload_length
            self._f_curr_frame_start_pos = self._f_curr_state_start_pos
            self._state = WSParserState.READ_HEADER

            if frame.opcode == WSMsgType.CLOSE:
                if frame.get_close_code() < 3000 and frame.get_close_code() not in ALLOWED_CLOSE_CODES:
                    raise PicowsError(WSCloseCode.PROTOCOL_ERROR,
                                         f"Invalid close code: {frame.get_close_code()}")

                if frame.payload_size > 0 and frame.payload_size < 2:
                    raise PicowsError(WSCloseCode.PROTOCOL_ERROR,
                                         f"Invalid close frame: {frame.fin} {frame.opcode} {frame.get_payload_as_bytes()}")

            return frame

        assert False, "we should never reach this state"

    cdef _handle_upgrade_response(self):
        cdef bytes data = PyBytes_FromStringAndSize(self._buffer.data, self._f_new_data_start_pos)
        response = data.split(b"\r\n\r\n", 1)
        if len(response) < 2:
            return None

        raw_headers, tail = response

        lines = raw_headers.split(b"\r\n")
        response_status_line = lines[0]

        response_headers = {}
        for line in lines[1:]:
            name, value = line.split(b":", maxsplit=1)
            response_headers[name.strip().decode().lower()] = value.strip().decode()

        # check handshake
        if response_status_line.decode().lower() != "http/1.1 101 switching protocols":
            raise RuntimeError(f"invalid status in upgrade response: {response_status_line}")

        connection_value = response_headers.get("connection")
        connection_value = connection_value if connection_value is None else connection_value.lower()
        if connection_value != "upgrade":
            raise RuntimeError(f"invalid connection header: {response_headers['connection']}")

        r_key = response_headers.get("sec-websocket-accept")
        match = base64.b64encode(hashlib.sha1(self.websocket_key_b64 + _WS_KEY).digest()).decode()
        if r_key != match:
            raise RuntimeError(f"invalid sec-websocket-accept response")

        memmove(self._buffer.data, self._buffer.data + len(raw_headers) + 4, self._buffer.size - len(raw_headers) - 4)
        self._f_new_data_start_pos = len(tail)
        self._state = WSParserState.READ_HEADER
        self.handshake_complete_future.set_result(None)
        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "WS handshake done, switch to upgraded state")

    cdef bytes read_upgrade_request(self):
        cdef bytes data = PyBytes_FromStringAndSize(self._buffer.data, self._f_new_data_start_pos)
        request = data.split(b"\r\n\r\n", 1)
        if len(request) < 2:
            return None

        self._logger.log(PICOWS_DEBUG_LL, "New data: %s", data)

        raw_headers, tail = request

        lines = raw_headers.split(b"\r\n")
        response_status_line = lines[0]

        headers = {}
        for line in lines[1:]:
            name, value = line.split(b":", maxsplit=1)
            headers[name.strip().decode().lower()] = value.strip().decode()

        if "websocket" != headers.get("upgrade"):
            raise RuntimeError(f"No WebSocket UPGRADE header: {raw_headers}\n Can 'Upgrade' only to 'websocket'")

        if "connection" not in headers:
            raise RuntimeError(f"No CONNECTION upgrade header: {raw_headers}\n")

        if "upgrade" != headers["connection"].lower():
            raise RuntimeError(f"CONNECTION header value is not 'upgrade' : {raw_headers}\n")

        version = headers.get("sec-websocket-version")
        if headers.get("sec-websocket-version") not in ("13", "8", "7"):
            raise RuntimeError(f"Upgrade requested to unsupported websocket version: {version}")

        key = headers.get("sec-websocket-key")
        try:
            if not key or len(base64.b64decode(key)) != 16:
                raise RuntimeError(f"Handshake error: {key!r}")
        except binascii.Error:
            raise RuntimeError(f"Handshake error: {key!r}") from None

        cdef bytes accept_val = base64.b64encode(hashlib.sha1(key.encode() + _WS_KEY).digest())

        memmove(self._buffer.data, self._buffer.data + len(raw_headers) + 4, self._buffer.size - len(raw_headers) - 4)

        self._f_new_data_start_pos = len(tail)
        self._state = WSParserState.READ_HEADER

        return accept_val


cdef class WSFrameBuilder:
    def __init__(self, bint is_client_side):
        self._write_buf = MemoryBuffer(1024)
        self.is_client_side = is_client_side

    cdef prepare_frame_in_external_buffer(self, WSMsgType opcode, uint8_t* msg_ptr, size_t msg_length):
        cdef:
            # Just fin byte and opcode
            # No support for rsv/compression
            uint8_t* header_ptr = msg_ptr
            uint64_t extended_payload_length_64
            uint32_t mask = <uint32_t> rand() if self.is_client_side else 0
            uint16_t extended_payload_length_16
            uint8_t first_byte = 0x80 | <uint8_t> opcode
            uint8_t second_byte = 0x80 if self.is_client_side else 0

        if msg_length < 126:
            header_ptr -= 2
            header_ptr[0] = first_byte
            header_ptr[1] = second_byte | <uint8_t>msg_length
        elif msg_length < (1 << 16):
            header_ptr -= 4
            header_ptr[0] = first_byte
            header_ptr[1] = second_byte | 126
            extended_payload_length_16 = htons(<uint16_t> msg_length)
            (<uint16_t*>(header_ptr + 2))[0] = extended_payload_length_16
        else:
            header_ptr -= 10
            header_ptr[0] = first_byte
            header_ptr[1] = second_byte | 127
            extended_payload_length_64 = htobe64(<uint64_t> msg_length)
            (<uint64_t*> (header_ptr + 2))[0] = extended_payload_length_64

        if self.is_client_side:
            _mask_payload(msg_ptr, msg_length, mask)

        cdef Py_ssize_t total_length = msg_length + (msg_ptr - header_ptr)

        return PyBytes_FromStringAndSize(<char*>header_ptr, total_length)
        # return PyMemoryView_FromMemory(header_ptr, total_length, PyBUF_READ)

    cpdef prepare_frame(self, WSMsgType opcode, message):
        """Send a frame over the websocket with message as its payload."""
        cdef:
            Py_buffer msg_buffer
            char* msg_ptr
            Py_ssize_t msg_length

        if message is None:
            msg_ptr = b""
            msg_length = 0
        elif PyBytes_CheckExact(message):
            # Just a small optimization for bytes type as the most used type for sending data
            msg_ptr = PyBytes_AS_STRING(message)
            msg_length = PyBytes_GET_SIZE(message)
        else:
            PyObject_GetBuffer(message, &msg_buffer, PyBUF_SIMPLE)
            msg_ptr = <char*>msg_buffer.buf
            msg_length = msg_buffer.len
            # We can already release because we still keep the reference to the message
            PyBuffer_Release(&msg_buffer)

        cdef:
            # Just fin byte and opcode
            # No support for rsv/compression
            uint8_t first_byte = 0x80 | <uint8_t>opcode
            uint8_t second_byte = 0x80 if self.is_client_side else 0
            uint32_t mask = <uint32_t>rand() if self.is_client_side else 0
            uint16_t extended_payload_length_16
            uint64_t extended_payload_length_64
            Py_ssize_t payload_start_idx

        self._write_buf.clear()
        self._write_buf.push_back(first_byte)

        if msg_length < 126:
            second_byte |= <uint8_t>msg_length
            self._write_buf.push_back(second_byte)
        elif msg_length < (1 << 16):
            second_byte |= 126
            self._write_buf.push_back(second_byte)
            extended_payload_length_16 = htons(<uint16_t>msg_length)
            self._write_buf.append(<const char*>&extended_payload_length_16, 2)
        else:
            second_byte |= 127
            extended_payload_length_64 = htobe64(<uint64_t>msg_length)
            self._write_buf.push_back(second_byte)
            self._write_buf.append(<const char*>&extended_payload_length_64, 8)

        if self.is_client_side:
            self._write_buf.append(<const char*>&mask, 4)
            payload_start_idx = self._write_buf.size
            self._write_buf.append(msg_ptr, msg_length)
            _mask_payload(<uint8_t*>self._write_buf.data + payload_start_idx, msg_length, mask)
        else:
            self._write_buf.append(msg_ptr, msg_length)

        # return PyMemoryView_FromMemory(<char*>&self._write_buf[0], self._write_buf.size(), PyBUF_READ)
        return PyBytes_FromStringAndSize(self._write_buf.data, self._write_buf.size)


cdef class WSListener:
    cpdef on_ws_connected(self, WSTransport transport):
        pass

    cpdef on_ws_frame(self, WSTransport transport, WSFrame frame):
        pass

    cpdef on_ws_disconnected(self, WSTransport transport):
        pass

    cpdef pause_writing(self):
        pass

    cpdef resume_writing(self):
        pass


cdef class WSTransport:
    def __init__(self, bint is_client_side, underlying_transport, logger, loop):
        self._transport = underlying_transport
        self._logger = logger
        self._disconnected_future = loop.create_future()
        self._frame_builder = WSFrameBuilder(is_client_side)

    cdef send_reuse_external_buffer(self, WSMsgType opcode, char* message, size_t message_size):
        frame = self._frame_builder.prepare_frame_in_external_buffer(opcode, <uint8_t*>message, message_size)
        self._transport.write(frame)

    cpdef send(self, WSMsgType opcode, message):
        """Send a frame over the websocket with message as its payload."""
        frame = self._frame_builder.prepare_frame(opcode, message)
        self._transport.write(frame)

    cpdef ping(self, message=None):
        self.send(WSMsgType.PING, message)

    cpdef pong(self, message=None):
        self.send(WSMsgType.PONG, message)

    cpdef disconnect(self, close_message=None):
        if self._transport.is_closing():
            return

        self.send(WSMsgType.CLOSE, close_message)
        self._transport.close()

    async def wait_until_closed(self):
        if not self._disconnected_future.done():
            await asyncio.shield(self._disconnected_future)

    cdef send_http_handshake(self, bytes ws_path, bytes host_port, bytes websocket_key_b64):
        initial_handshake = (b"GET %b HTTP/1.1\r\n"
                             b"Host: %b\r\n"
                             b"Upgrade: websocket\r\n"
                             b"Connection: Upgrade\r\n"
                             b"Sec-WebSocket-Version: 13\r\n"
                             b"Sec-WebSocket-Key: %b\r\n"
                             b"\r\n" % (ws_path, host_port, websocket_key_b64))
        self._transport.write(initial_handshake)

    cdef send_http_handshake_response(self, bytes accept_val):
        cdef bytes handshake_response = (b"HTTP/1.1 101 Switching Protocols\r\n"
                                         b"Connection: upgrade\r\n"
                                         b"Upgrade: websocket\r\n"
                                         b"Sec-WebSocket-Accept: %b\r\n"
                                         b"\r\n" % (accept_val,))

        self._logger.log(PICOWS_DEBUG_LL, "Send upgrade response: %s", handshake_response)
        self._transport.write(handshake_response)


    cdef mark_disconnected(self):
        if not self._disconnected_future.done():
            self._disconnected_future.set_result(None)


cdef class WSProtocol:
    cdef:
        bytes _host_port
        bytes _ws_path
        object _logger                          #: Logger
        WSFrameParser _frame_parser
        object _loop
        object _handshake_timeout_handle
        bint _is_client_side
        bint _log_debug_enabled

        WSTransport transport
        WSListener listener

    def __init__(self, str host_port, str ws_path, bint is_client_side, ws_listener_factory, str logger_name):
        self._host_port = host_port.encode()
        self._ws_path = ws_path.encode() if ws_path else b"/"
        self._logger = logging.getLogger(f"pico_ws.{logger_name}")
        self._frame_parser = None
        self._loop = asyncio.get_running_loop()
        self._handshake_timeout_handle = None
        self._is_client_side = is_client_side
        self._log_debug_enabled = self._logger.isEnabledFor(PICOWS_DEBUG_LL)

        self.transport = None
        self.listener = ws_listener_factory()

    def connection_made(self, transport: asyncio.Transport):
        sock = transport.get_extra_info('socket')
        peername = transport.get_extra_info('peername')
        sockname = transport.get_extra_info('sockname')

        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)

        self._logger = self._logger.getChild(str(sock.fileno()))
        self._frame_parser = WSFrameParser(self._logger)

        if self._is_client_side:
            self._logger.info("WS connection established: %s -> %s, recvbuf=%d, sendbuf=%d, quickack=%d, nodelay=%d",
                              peername, sockname,
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                              sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK),
                              sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
        else:
            self._logger.info("New connection accepted: %s -> %s, recvbuf=%d, sendbuf=%d, quickack=%d, nodelay=%d",
                              peername, sockname,
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                              sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK),
                              sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))


        self.transport = WSTransport(self._is_client_side, transport, self._logger, self._loop)

        if self._is_client_side:
            self.transport.send_http_handshake(self._ws_path, self._host_port, self._frame_parser.websocket_key_b64)
        else:
            self._handshake_timeout_handle = self._loop.call_later(2, self._handshake_timeout)

    def connection_lost(self, exc):
        self._logger.info("Disconnected")

        if self._frame_parser.handshake_complete_future.done():
            self.listener.on_ws_disconnected(self.transport)

        if not self._frame_parser.handshake_complete_future.done():
            self._frame_parser.handshake_complete_future.set_result(None)

        self.transport.mark_disconnected()

        if self._handshake_timeout_handle is not None:
            self._handshake_timeout_handle.cancel()

    def eof_received(self) -> bool:
        self._logger.debug("WS eof received")
        # Returning False here means that the transport should close itself
        return False

    def pause_writing(self):
        self._logger.warning("Protocol writing pause requested, crossed writing buffer high-watermark")
        self.listener.pause_writing()

    def resume_writing(self):
        self._logger.warning("Protocol writing resume requested, crossed writing buffer low-watermark,")
        self.listener.resume_writing()

    cdef _handle_new_data(self):
        if not self._is_client_side:
            accept_val = self._frame_parser.read_upgrade_request()
            if accept_val is not None:
                self.transport.send_http_handshake_response(accept_val)
                self._frame_parser.handshake_complete_future.set_result(None)
                self._handshake_timeout_handle.cancel()
                self._handshake_timeout_handle = None
                self.listener.on_ws_connected(self.transport)

        cdef WSFrame frame = self._get_next_frame()
        if frame is None:
            return

        cdef WSFrame next_frame = self._get_next_frame()
        if next_frame is None:
            frame.last_in_buffer = 1
            self._invoke_on_ws_frame(frame)
            self._frame_parser.shrink_buffer()
            return
        else:
            self._invoke_on_ws_frame(frame)

        while next_frame is not None:
            frame = next_frame
            next_frame = self._get_next_frame()
            if next_frame is None:
                frame.last_in_buffer = 1
            self._invoke_on_ws_frame(frame)

        self._frame_parser.shrink_buffer()

    def data_received(self, bytes data):
        self._frame_parser.feed_data(data)
        self._handle_new_data()

    def get_buffer(self, Py_ssize_t size_hint):
        return self._frame_parser.get_buffer(size_hint)

    def buffer_updated(self, Py_ssize_t nbytes):
        self._frame_parser.buffer_updated(nbytes)
        self._handle_new_data()

    cdef WSFrame _get_next_frame(self):
        cdef WSFrame frame
        try:
            return self._frame_parser.get_next_frame()
        except:
            self._logger.exception("WS parser failure, initiate disconnect")
            self.transport.disconnect()

    cdef _invoke_on_ws_frame(self, WSFrame frame):
        try:
            self.listener.on_ws_frame(self.transport, frame)
        except:
            self._logger.exception("Unhandled exception in on_ws_frame, initiate disconnect")
            self.transport.disconnect()

    async def wait_until_handshake_complete(self):
        await asyncio.shield(self._frame_parser.handshake_complete_future)

    def _handshake_timeout(self):
        self._logger.info("Handshake timeout, the client hasn't requested upgrade within required time, close connection")
        self.transport.close()


async def ws_connect(str url, ws_listener_factory, str logger_name, ssl_context=None):
    url_parts = urllib.parse.urlparse(url, allow_fragments=False)

    if url_parts.scheme == "wss":
        ssl_context = ssl_context or True
        port = url_parts.port or 443
        ssl_handshake_timeout = 2
        ssl_shutdown_timeout = 2
    elif url_parts.scheme == "ws":
        ssl_context = None
        port = url_parts.port or 80
        ssl_handshake_timeout = None
        ssl_shutdown_timeout = None
    else:
        raise ValueError(f"invalid url scheme: {url}")

    ws_protocol_factory = lambda: WSProtocol(url_parts.netloc, url_parts.path, True, ws_listener_factory, logger_name)

    cdef WSProtocol ws_protocol

    (_, ws_protocol) = await asyncio.get_running_loop().create_connection(
        ws_protocol_factory, url_parts.hostname, port, ssl=ssl_context,
        ssl_handshake_timeout=ssl_handshake_timeout, ssl_shutdown_timeout=ssl_shutdown_timeout)

    await ws_protocol.wait_until_handshake_complete()
    ws_protocol.listener.on_ws_connected(ws_protocol.transport)

    return ws_protocol.transport, ws_protocol.listener


async def ws_create_server(str url, ws_listener_factory, str logger_name, ssl_context=None) -> asyncio.Server:
    url_parts = urllib.parse.urlparse(url, allow_fragments=False)

    if url_parts.scheme == "wss":
        ssl_context = ssl_context or True
        port = url_parts.port or 443
        ssl_handshake_timeout = 2
        ssl_shutdown_timeout = 2
    elif url_parts.scheme == "ws":
        ssl_context = None
        port = url_parts.port or 80
        ssl_handshake_timeout = None
        ssl_shutdown_timeout = None
    else:
        raise ValueError(f"invalid url scheme: {url}")

    ws_protocol_factory = lambda: WSProtocol(url_parts.netloc, url_parts.path, False, ws_listener_factory, logger_name)

    cdef WSProtocol ws_protocol

    server = await asyncio.get_running_loop().create_server(
        ws_protocol_factory,
        host=url_parts.hostname, port=port,
        ssl=ssl_context,
        ssl_handshake_timeout=ssl_handshake_timeout, ssl_shutdown_timeout=ssl_shutdown_timeout,
        start_serving=False)

    return server
