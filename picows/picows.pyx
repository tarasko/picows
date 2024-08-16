import asyncio
import base64
import binascii
import hashlib
import logging
import os
import socket
import ssl
import struct
import urllib.parse
from ssl import SSLContext
from typing import cast, Tuple, Optional, Callable, Union

cimport cython

from cpython.bytes cimport PyBytes_GET_SIZE, PyBytes_AS_STRING, PyBytes_FromStringAndSize, PyBytes_CheckExact
from cpython.memoryview cimport PyMemoryView_FromMemory
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free
from cpython.buffer cimport PyBUF_WRITE, PyBUF_READ, PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.unicode cimport PyUnicode_FromStringAndSize, PyUnicode_DecodeASCII

from libc.string cimport memmove, memcpy
from libc.stdlib cimport rand

PICOWS_DEBUG_LL = 9


cdef extern from * nogil:
    """
    #if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)
    #	define __WINDOWS__
    #endif

    #if defined(__linux__)
      #include <arpa/inet.h>
      #include <endian.h>
    #elif defined(__APPLE__)
      #include <arpa/inet.h>
      #include <libkern/OSByteOrder.h>
      #define be64toh(x) OSSwapBigToHostInt64(x)
      #define htobe64(x) OSSwapHostToBigInt64(x)
    #elif defined(__OpenBSD__)
      #include <arpa/inet.h>
      #include <sys/endian.h>
    #elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
      #include <arpa/inet.h>
      #include <sys/endian.h>
      #define be64toh(x) betoh64(x)
    #elif defined(__WINDOWS__)
      #include <winsock2.h>
      #if BYTE_ORDER == LITTLE_ENDIAN
        #define be64toh(x) ntohll(x)
        #define htobe64(x) htonll(x)
      #elif BYTE_ORDER == BIG_ENDIAN
        #define be64toh(x) (x)
        #define htobe64(x) (x)
      #endif
    #else
      error byte order not supported
    #endif
    """

    # Network order is big-endian

    uint32_t ntohl(uint32_t)
    uint32_t htonl(uint32_t)
    uint16_t ntohs(uint16_t)
    uint16_t htons(uint16_t)

    uint64_t be64toh(uint64_t)
    uint64_t htobe64(uint64_t)


class WSError(Exception):
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
    """
    Received websocket frame.

    Internally WSFrame just points to a chunk of memory in the receiving buffer without copying or owning memory.\n
    .. DANGER::
        Only use WSFrame object during :any:`WSListener.on_ws_frame` callback. WSFrame objects are essentially just
        pointers to the underlying receiving buffer. After :any:`WSListener.on_ws_frame` has completed the buffer
        will be reused for the new incoming data.

    In order to actually copy payload use one of the `get_*` methods.
    """

    cpdef bytes get_payload_as_bytes(self):
        """
        :return: a new bytes object with a copy of frame payload.
        
        This method does not cache results. Payload is copied and a new bytes object is created every time this method is called.
        """
        return PyBytes_FromStringAndSize(self.payload_ptr, <Py_ssize_t>self.payload_size)

    cpdef str get_payload_as_utf8_text(self):
        """
        :return: a new str object with a copy of frame payload.
        
        This method will throw if payload does not contain valid UTF8 text.
        
        This method does not cache results. Payload is copied and a new str object is created every time this method is called.
        """
        return PyUnicode_FromStringAndSize(self.payload_ptr, <Py_ssize_t>self.payload_size)

    cpdef str get_payload_as_ascii_text(self):
        """
        :return: a new str object with a copy of frame payload.
        
        This method will throw if payload does not contain valid ASCII 7 text.
        
        This method does not cache results. Payload is copied and a new str object is created every time this method is called.
        """
        return PyUnicode_DecodeASCII(self.payload_ptr, <Py_ssize_t>self.payload_size, NULL)

    cpdef object get_payload_as_memoryview(self):
        """
        :return: continous memoryview to a parser buffer with payload.
        
        .. DANGER::
            Returned memoryview does NOT own the underlying memory. 
            The content will be invalidated after :any:`WSListener.on_ws_frame` has completed.
            Please process payload or copy it as soon as possible.
        """
        return PyMemoryView_FromMemory(self.payload_ptr, <Py_ssize_t>self.payload_size, PyBUF_READ)

    cpdef WSCloseCode get_close_code(self):
        """
        :return: :any:`WSCloseCode` 
        
        This method is only valid for WSMsgType.CLOSE frames.        
        """

        assert self.msg_type == WSMsgType.CLOSE, "get_close_code can be called only for CLOSE frames"

        if self.payload_size < 2:
            return WSCloseCode.NO_INFO
        else:
            return <WSCloseCode>ntohs((<uint16_t *>self.payload_ptr)[0])

    cpdef bytes get_close_message(self):
        """
        :return: a new bytes object with a close message. If there is no close message then returns None. 
        
        This method is only valid for WSMsgType.CLOSE frames.
        """

        assert self.msg_type == WSMsgType.CLOSE, "get_close_message can be called only for CLOSE frames"

        if self.payload_size <= 2:
            return None
        else:
            return PyBytes_FromStringAndSize(self.payload_ptr + 2, <Py_ssize_t>self.payload_size - 2)

    def __str__(self):
        return (f"WSFrame({WSMsgType(self.msg_type).name}, fin={True if self.fin else False}, "
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


cdef class WSFrameBuilder:
    def __init__(self, bint is_client_side):
        self._write_buf = MemoryBuffer(1024)
        self.is_client_side = is_client_side

    cdef prepare_frame_in_external_buffer(self, WSMsgType msg_type, uint8_t* msg_ptr, size_t msg_length):
        cdef:
            # Just fin byte and msg_type
            # No support for rsv/compression
            uint8_t* header_ptr = msg_ptr
            uint64_t extended_payload_length_64
            uint32_t mask = <uint32_t> rand() if self.is_client_side else 0
            uint16_t extended_payload_length_16
            uint8_t first_byte = 0x80 | <uint8_t> msg_type
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

    cpdef prepare_frame(self, WSMsgType msg_type, message):
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
            # Just fin byte and msg_type
            # No support for rsv/compression
            uint8_t first_byte = 0x80 | <uint8_t>msg_type
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
    """
    Base class for user handlers.

    All `on_ws_*` methods receive `transport` as a first argument for convenience. It is guaranteed that passed
    `transport` object is always the same for the same connection.
    """

    cpdef on_ws_connected(self, WSTransport transport):
        """        
        :param transport: :any:`WSTransport` object      

        Called after websocket handshake is complete and websocket is ready to send and receive frames.
        """
        pass

    cpdef on_ws_frame(self, WSTransport transport, WSFrame frame):
        """
        :param transport: :any:`WSTransport` object
        :param frame: :any:`WSFrame` object            

        Called when a new frame is received.
        
        .. DANGER::
            WSFrame is essentially just a pointer to a chunk of memory in the receiving buffer. It does not own 
            the memory. Do NOT cache or store WSFrame object for later processing because the data may be invalidated
            after :any:`WSListener.on_ws_frame` is complete.
            Process the payload immediatelly or just copy it with one of `WSFrame.get_*` methods.            
        """
        pass

    cpdef on_ws_disconnected(self, WSTransport transport):
        """
        :param transport: :any:`WSTransport`
        
        Called when websocket has been disconnected.
        """
        pass

    cpdef pause_writing(self):
        """
        Called when the underlying transport’s buffer goes over the high watermark.
        """
        pass

    cpdef resume_writing(self):
        """
        Called when the underlying transport’s buffer drains below the low watermark.
        """
        pass


cdef class WSTransport:
    def __init__(self, bint is_client_side, underlying_transport, logger, loop):
        self._transport = underlying_transport
        self._logger = logger
        self._disconnected_future = loop.create_future()
        self._frame_builder = WSFrameBuilder(is_client_side)

    cdef send_reuse_external_buffer(self, WSMsgType msg_type, char* message, size_t message_size):
        frame = self._frame_builder.prepare_frame_in_external_buffer(msg_type, <uint8_t*>message, message_size)
        self._transport.write(frame)

    cpdef send(self, WSMsgType msg_type, message):
        """        
        :param msg_type: :any:`WSMsgType` enum value\n 
        :param message: an optional bytes-like object
        
        Send a frame over websocket with a message as its payload.        
        """
        frame = self._frame_builder.prepare_frame(msg_type, message)
        self._transport.write(frame)

    cpdef send_ping(self, message=None):
        """
        :param message: an optional bytes-like object

        Send a PING control frame with an optional message.
        """
        self.send(WSMsgType.PING, message)

    cpdef send_pong(self, message=None):
        """
        :param message: an optional bytes-like object

        Send a PONG control frame with an optional message.
        """
        self.send(WSMsgType.PONG, message)

    cpdef send_close(self, WSCloseCode close_code=WSCloseCode.NO_INFO, close_message=None):
        """
        :param close_code: :any:`WSCloseCode` value                
        :param close_message: an optional bytes-like object        

        Send a CLOSE control frame with an optional message.
        This method doesn't disconnect the underlying transport.
        Does nothing if the underlying transport is already disconnected.        
        """
        if self._transport.is_closing():
            return

        cdef bytes close_payload = struct.pack("!H", <uint16_t>close_code)
        if close_message is not None:
            close_payload += close_message

        self.send(WSMsgType.CLOSE, close_payload)

    cpdef disconnect(self):
        """
        Immediately disconnect the underlying transport. 
        It is ok to call this method multiple times. It does nothing if the transport is already disconnected.         
        """
        if self._transport.is_closing():
            return
        self._transport.close()

    async def wait_until_closed(self):
        """
        Coroutine that conveniently allows to wait until websocket is completely closed
        (underlying transport is disconnected)
        """
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
        WSTransport transport
        WSListener listener

        bytes _host_port
        bytes _ws_path
        object _logger                          #: Logger
        bint _log_debug_enabled
        bint _is_client_side
        bint _disconnect_on_exception

        object _loop

        object _handshake_timeout
        object _handshake_timeout_handle
        object _handshake_complete_future
        Py_ssize_t _upgrade_request_max_size

        bytes _websocket_key_b64
        size_t _max_frame_size

        # The following are the parts of an unfinished frame
        # Once the frame is finished WSFrame is created and returned
        WSParserState _state
        MemoryBuffer _buffer
        size_t _f_new_data_start_pos
        size_t _f_curr_state_start_pos
        size_t _f_curr_frame_start_pos
        uint64_t _f_payload_length
        size_t _f_payload_start_pos
        WSMsgType _f_msg_type
        uint32_t _f_mask
        uint8_t _f_fin
        uint8_t _f_has_mask
        uint8_t _f_payload_length_flag

    def __init__(self, str host_port, str ws_path, bint is_client_side, ws_listener_factory, str logger_name,
                 bint disconnect_on_exception, websocket_handshake_timeout):
        self.transport = None
        self.listener = ws_listener_factory()

        self._host_port = host_port.encode()
        self._ws_path = ws_path.encode() if ws_path else b"/"
        self._logger = logging.getLogger(f"pico_ws.{logger_name}")
        self._log_debug_enabled = self._logger.isEnabledFor(PICOWS_DEBUG_LL)
        self._is_client_side = is_client_side
        self._disconnect_on_exception = disconnect_on_exception

        self._loop = asyncio.get_running_loop()

        self._handshake_timeout = websocket_handshake_timeout
        self._handshake_timeout_handle = None
        self._handshake_complete_future = self._loop.create_future()
        self._upgrade_request_max_size = 16 * 1024

        self._websocket_key_b64 = base64.b64encode(os.urandom(16))
        self._max_frame_size = 1024 * 1024

        self._state = WSParserState.WAIT_UPGRADE_RESPONSE
        self._buffer = MemoryBuffer()
        self._f_new_data_start_pos = 0
        self._f_curr_state_start_pos = 0
        self._f_curr_frame_start_pos = 0
        self._f_payload_length = 0
        self._f_payload_start_pos = 0
        self._f_msg_type = WSMsgType.CLOSE
        self._f_mask = 0
        self._f_fin = 0
        self._f_has_mask = 0
        self._f_payload_length_flag = 0

    def connection_made(self, transport: asyncio.Transport):
        sock = transport.get_extra_info('socket')
        peername = transport.get_extra_info('peername')
        sockname = transport.get_extra_info('sockname')

        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if hasattr(socket, "TCP_QUICKACK"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)

        self._logger = self._logger.getChild(str(sock.fileno()))

        quickack = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK) if hasattr(socket, "TCP_QUICKACK") else False

        if self._is_client_side:
            self._logger.info("WS connection established: %s -> %s, recvbuf=%d, sendbuf=%d, quickack=%d, nodelay=%d",
                              peername, sockname,
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                              quickack,
                              sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
        else:
            self._logger.info("New connection accepted: %s -> %s, recvbuf=%d, sendbuf=%d, quickack=%d, nodelay=%d",
                              peername, sockname,
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                              quickack,
                              sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))


        self.transport = WSTransport(self._is_client_side, transport, self._logger, self._loop)

        if self._is_client_side:
            self.transport.send_http_handshake(self._ws_path, self._host_port, self._websocket_key_b64)
            self._handshake_timeout_handle = self._loop.call_later(
                self._handshake_timeout, self._handshake_timeout_callback)
        else:
            self._handshake_timeout_handle = self._loop.call_later(
                self._handshake_timeout, self._handshake_timeout_callback)

    def connection_lost(self, exc):
        self._logger.info("Disconnected")

        if self._handshake_complete_future.done():
            self.listener.on_ws_disconnected(self.transport)

        if not self._handshake_complete_future.done():
            self._handshake_complete_future.set_result(None)

        if self._handshake_timeout_handle is not None:
            self._handshake_timeout_handle.cancel()

        self.transport.mark_disconnected()

    def eof_received(self) -> bool:
        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "EOF marker received")
        # Returning False here means that the transport should close itself
        return False

    def pause_writing(self):
        self._logger.warning("Protocol writing pause requested, crossed writing buffer high-watermark")
        self.listener.pause_writing()

    def resume_writing(self):
        self._logger.warning("Protocol writing resume requested, crossed writing buffer low-watermark,")
        self.listener.resume_writing()

    def data_received(self, bytes data):
        cdef:
            const char * ptr = PyBytes_AS_STRING(data)
            size_t sz = PyBytes_GET_SIZE(data)

        # Leave some space for simd parsers like simdjson, they required extra space beyond normal data to make sure
        # that vector reads don't cause access violation
        if self._buffer.size - self._f_new_data_start_pos < (sz + 64):
            self._buffer.resize(self._f_new_data_start_pos + sz + 64)

        memcpy(self._buffer.data + self._f_new_data_start_pos, ptr, sz)
        self._f_new_data_start_pos += sz

        self._handle_new_data()

    def get_buffer(self, Py_ssize_t size_hint):
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

    def buffer_updated(self, Py_ssize_t nbytes):
        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "buffer_updated(%d), write_pos %d -> %d", nbytes,
                             self._f_new_data_start_pos, self._f_new_data_start_pos + nbytes)
        self._f_new_data_start_pos += nbytes
        self._handle_new_data()

    async def wait_until_handshake_complete(self):
        await asyncio.shield(self._handshake_complete_future)

    cdef _handle_new_data(self):
        if self._state == WSParserState.WAIT_UPGRADE_RESPONSE:
            if self._is_client_side:
                self._handle_upgrade_response()
                if self._state == WSParserState.WAIT_UPGRADE_RESPONSE:
                    # Upgrade response hasn't fully arrived yet
                    return

            else:
                accept_val = self._read_upgrade_request()
                if accept_val is None:
                    # Upgrade request hasn't fully arrived yet
                    return

                self.transport.send_http_handshake_response(accept_val)

            self._handshake_complete_future.set_result(None)
            self._handshake_timeout_handle.cancel()
            self._handshake_timeout_handle = None
            self._invoke_on_ws_connected()

        cdef WSFrame frame = self._get_next_frame()
        if frame is None:
            return

        cdef WSFrame next_frame = self._get_next_frame()
        if next_frame is None:
            frame.last_in_buffer = 1
            self._invoke_on_ws_frame(frame)
            self._shrink_buffer()
            return
        else:
            self._invoke_on_ws_frame(frame)

        while next_frame is not None:
            frame = next_frame
            next_frame = self._get_next_frame()
            if next_frame is None:
                frame.last_in_buffer = 1
            self._invoke_on_ws_frame(frame)

        self._shrink_buffer()

    cdef bytes _read_upgrade_request(self):
        cdef bytes data = PyBytes_FromStringAndSize(self._buffer.data, self._f_new_data_start_pos)
        request = data.split(b"\r\n\r\n", 1)
        if len(request) < 2:
            if len(data) >= self._upgrade_request_max_size:
                self.transport.disconnect()
                self._logger.info("Disconnect because upgrade request violated max_size threshold: %d", 16*1024)

            return None

        if len(request[0]) >= self._upgrade_request_max_size:
            self.transport.disconnect()
            self._logger.info("Disconnect because upgrade request violated max_size threshold: %d", 16*1024)
            return None

        if self._log_debug_enabled:
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
        match = base64.b64encode(hashlib.sha1(self._websocket_key_b64 + _WS_KEY).digest()).decode()
        if r_key != match:
            raise RuntimeError(f"invalid sec-websocket-accept response")

        memmove(self._buffer.data, self._buffer.data + len(raw_headers) + 4, self._buffer.size - len(raw_headers) - 4)
        self._f_new_data_start_pos = len(tail)
        self._state = WSParserState.READ_HEADER
        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "WS handshake done, switch to upgraded state")

    cdef WSFrame _get_next_frame(self):
        cdef WSFrame frame
        try:
            return self._get_next_frame_impl()
        except WSError as ex:
            self._logger.error("WS parser error: %s, initiate disconnect", ex.args)
            self.transport.send_close(ex.args[0], ex.args[1].encode())
            self.transport.disconnect()
        except:
            self._logger.exception("WS parser failure, initiate disconnect")
            self.transport.send_close(WSCloseCode.PROTOCOL_ERROR)
            self.transport.disconnect()

    cdef WSFrame _get_next_frame_impl(self): #  -> Optional[WSFrame]
        """Return the next frame from the socket."""
        cdef:
            uint8_t first_byte
            uint8_t second_byte
            uint8_t rsv1, rsv2, rsv3
            WSFrame frame

        if self._state == WSParserState.READ_HEADER:
            if self._f_new_data_start_pos - self._f_curr_state_start_pos < 2:
                return None

            first_byte = <uint8_t>self._buffer.data[self._f_curr_state_start_pos]
            second_byte = <uint8_t>self._buffer.data[self._f_curr_state_start_pos + 1]

            self._f_fin = (first_byte >> 7) & 1
            rsv1 = (first_byte >> 6) & 1
            rsv2 = (first_byte >> 5) & 1
            rsv3 = (first_byte >> 4) & 1
            self._f_msg_type = <WSMsgType>(first_byte & 0xF)

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
                    max(self._f_new_data_start_pos - self._f_curr_state_start_pos, <size_t>64)
                )
                raise WSError(
                    WSCloseCode.PROTOCOL_ERROR,
                    f"Received frame with non-zero reserved bits, rsv1={rsv1}, rsv2={rsv2}, rsv3={rsv3}, msg_type={self._f_msg_type}: {mem_dump}",
                )

            if self._f_msg_type > 0x7 and not self._f_fin:
                raise WSError(
                    WSCloseCode.PROTOCOL_ERROR,
                    "Received fragmented control frame",
                )

            self._f_has_mask = (second_byte >> 7) & 1
            self._f_payload_length_flag = second_byte & 0x7F

            # Control frames MUST have a payload
            # length of 125 bytes or less
            if self._f_msg_type > 0x7 and self._f_payload_length_flag > 125:
                raise WSError(
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

            if self._f_payload_length > self._max_frame_size:
                raise WSError(WSCloseCode.PROTOCOL_ERROR, f"Frame payload size violates max allowed size {self._f_payload_length} > {self._max_frame_size}")

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
            frame.msg_type = self._f_msg_type
            frame.fin = self._f_fin
            frame.last_in_buffer = 0

            self._f_curr_state_start_pos += self._f_payload_length
            self._f_curr_frame_start_pos = self._f_curr_state_start_pos
            self._state = WSParserState.READ_HEADER

            if frame.msg_type == WSMsgType.CLOSE:
                if frame.get_close_code() < 3000 and frame.get_close_code() not in ALLOWED_CLOSE_CODES:
                    raise WSError(WSCloseCode.PROTOCOL_ERROR,
                                         f"Invalid close code: {frame.get_close_code()}")

                if frame.payload_size > 0 and frame.payload_size < 2:
                    raise WSError(WSCloseCode.PROTOCOL_ERROR,
                                         f"Invalid close frame: {frame.fin} {frame.msg_type} {frame.get_payload_as_bytes()}")

            return frame

        assert False, "we should never reach this state"

    cdef _invoke_on_ws_connected(self):
        try:
            self.listener.on_ws_connected(self.transport)
        except Exception as e:
            if self._disconnect_on_exception:
                self._logger.exception("Unhandled exception in on_ws_connected, initiate disconnect")
                self.transport.send_close(WSCloseCode.INTERNAL_ERROR)
                self.transport.disconnect()
            else:
                self._logger.exception("Unhandled exception in on_ws_connected")

    cdef _invoke_on_ws_frame(self, WSFrame frame):
        try:
            self.listener.on_ws_frame(self.transport, frame)
        except Exception as e:
            if self._disconnect_on_exception:
                self._logger.exception("Unhandled exception in on_ws_frame, initiate disconnect")
                self.transport.send_close(WSCloseCode.INTERNAL_ERROR)
                self.transport.disconnect()
            else:
                self._logger.exception("Unhandled exception in on_ws_frame")

    cdef _shrink_buffer(self):
        if self._f_curr_frame_start_pos > 0:
            memmove(self._buffer.data,
                    self._buffer.data + self._f_curr_frame_start_pos,
                    self._f_new_data_start_pos - self._f_curr_frame_start_pos)

            self._f_new_data_start_pos -= self._f_curr_frame_start_pos
            self._f_curr_state_start_pos -= self._f_curr_frame_start_pos
            self._f_payload_start_pos -= self._f_curr_frame_start_pos
            self._f_curr_frame_start_pos = 0

    def _handshake_timeout_callback(self):
        self._logger.info("Handshake timeout, the client hasn't requested upgrade within required time, close connection")
        self.transport.disconnect()


async def ws_connect(str url: str,
                     ws_listener_factory: Callable[[], WSListener],
                     str logger_name: str,
                     ssl: Optional[Union[bool, SSLContext]]=None,
                     bint disconnect_on_exception: bool=True,
                     ssl_handshake_timeout: int=5,
                     ssl_shutdown_timeout: int=5,
                     websocket_handshake_timeout: int=5,
                     local_addr: Optional[Tuple[str, int]]=None,
                     ) -> Tuple[WSTransport, WSListener]:
    """
    :param url: Destination URL
    :param ws_listener_factory:
        A parameterless factory function that returns a user handler. User handler has to derive from :any:`WSListener`.
    :param logger_name:
        picows will use `picows.<logger_name>` logger to do all the logging.
    :param ssl: optional SSLContext to override default one when wss scheme is used
    :param disconnect_on_exception:
        Indicates whether the client should initiate disconnect on any exception
        thrown from WSListener.on_ws* callbacks
    :param ssl_handshake_timeout:
        is (for a TLS connection) the time in seconds to wait for the TLS handshake to complete before aborting the connection.
    :param ssl_shutdown_timeout:
        is the time in seconds to wait for the SSL shutdown to complete before aborting the connection.
    :param websocket_handshake_timeout:
        is the time in seconds to wait for the websocket server to reply to websocket handshake request
    :param local_addr:
        if given, is a (local_host, local_port) tuple used to bind the socket locally. The local_host and local_port
        are looked up using getaddrinfo(), similarly to host and port from url.
    :return: :any:`WSTransport` object and a user handler returned by `ws_listener_factory()'

    Open a websocket connection to a given URL.
    """

    url_parts = urllib.parse.urlparse(url, allow_fragments=False)

    if url_parts.scheme == "wss":
        if ssl is None:
            ssl = True
        port = url_parts.port or 443
    elif url_parts.scheme == "ws":
        ssl = None
        ssl_handshake_timeout = None
        ssl_shutdown_timeout = None
        port = url_parts.port or 80
    else:
        raise ValueError(f"invalid url scheme: {url}")

    ws_protocol_factory = lambda: WSProtocol(url_parts.netloc, url_parts.path, True, ws_listener_factory,
                                             logger_name, disconnect_on_exception, websocket_handshake_timeout)

    cdef WSProtocol ws_protocol

    (_, ws_protocol) = await asyncio.get_running_loop().create_connection(
        ws_protocol_factory, url_parts.hostname, port,
        local_addr=local_addr,
        ssl=ssl,
        ssl_handshake_timeout=ssl_handshake_timeout,
        ssl_shutdown_timeout=ssl_shutdown_timeout)

    await ws_protocol.wait_until_handshake_complete()

    return ws_protocol.transport, ws_protocol.listener


async def ws_create_server(str url,
                           ws_listener_factory,
                           str logger_name,
                           ssl_context=None,
                           disconnect_on_exception=True,
                           ssl_handshake_timeout: int=5,
                           ssl_shutdown_timeout: int=5,
                           websocket_handshake_timeout: int=5,
                           reuse_port: bool=None,
                           start_serving: bool=False
                           ) -> asyncio.Server:
    """
    :param url:
        Defines which interface and port to bind on and what scheme ('ws' or 'wss') to use.
        Currently, the path part of the URL is completely ignored.
    :param ws_listener_factory:
        A parameterless factory function that returns a user handler for a newly accepted connection.
        User handler has to derive from :any:`WSListener`.
    :param logger_name:
        picows will use `picows.<logger_name>` logger to do all the logging.
    :param ssl: optional SSLContext to override default one when wss scheme is used
    :param disconnect_on_exception:
        Indicates whether the client should initiate disconnect on any exception
        thrown from WSListener.on_ws* callbacks
    :param ssl_handshake_timeout:
        is (for a TLS connection) the time in seconds to wait for the TLS handshake to complete before aborting the connection.
    :param ssl_shutdown_timeout:
        is the time in seconds to wait for the SSL shutdown to complete before aborting the connection.
    :param websocket_handshake_timeout:
        is the time in seconds to wait for the websocket server to receive to websocket handshake request before aborting the connection.
    :param reuse_port:
        tells the kernel to allow this endpoint to be bound to the same port as other existing endpoints are bound to,
        so long as they all set this flag when being created. This option is not supported on Windows
    :param start_serving:
        causes the created server to start accepting connections immediately. When set to False,
        the user should await on `Server.start_serving()` or `Server.serve_forever()` to make the server to start
        accepting connections.
    :return: asyncio.Server object

    Create a websocket server listening on interface and port specified by `url`.
    """
    url_parts = urllib.parse.urlparse(url, allow_fragments=False)

    if url_parts.scheme == "wss":
        if ssl_context is None:
            ssl_context = SSLContext(ssl.PROTOCOL_TLS_SERVER)
        port = url_parts.port or 443
    elif url_parts.scheme == "ws":
        ssl_context = None
        ssl_handshake_timeout = None
        ssl_shutdown_timeout = None
        port = url_parts.port or 80
    else:
        raise ValueError(f"invalid url scheme: {url}")

    ws_protocol_factory = lambda: WSProtocol(url_parts.netloc, url_parts.path, False, ws_listener_factory, logger_name,
                                             disconnect_on_exception, websocket_handshake_timeout)

    cdef WSProtocol ws_protocol

    return await asyncio.get_running_loop().create_server(
        ws_protocol_factory,
        host=url_parts.hostname, port=port,
        ssl=ssl_context,
        ssl_handshake_timeout=ssl_handshake_timeout,
        ssl_shutdown_timeout=ssl_shutdown_timeout,
        reuse_port=reuse_port,
        start_serving=start_serving)
