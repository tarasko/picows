import asyncio
import weakref
import binascii
import logging
import os
import socket
from http import HTTPStatus
from base64 import b64encode, b64decode
from hashlib import sha1

from multidict import CIMultiDict

cimport cython
from cpython.bytes cimport PyBytes_GET_SIZE, PyBytes_AS_STRING, PyBytes_FromStringAndSize, PyBytes_CheckExact
from cpython.bytearray cimport PyByteArray_AS_STRING, PyByteArray_GET_SIZE, PyByteArray_CheckExact
from cpython.memoryview cimport PyMemoryView_FromMemory
from cpython.mem cimport PyMem_Malloc, PyMem_Realloc, PyMem_Free
from cpython.buffer cimport PyBUF_WRITE, PyBUF_READ, PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.unicode cimport PyUnicode_FromStringAndSize, PyUnicode_DecodeASCII

from libc cimport errno
from libc.string cimport memmove, memcpy
from libc.stdlib cimport rand

from .types import (PICOWS_DEBUG_LL, WSUpgradeRequest, WSUpgradeResponse,
                    WSUpgradeResponseWithListener,
                    WSError, _WSParserError, add_extra_headers)

# When picows would like to disconnect peer (due to protocol violation or other failures), CLOSE frame is sent first.
# Then disconnect is scheduled with a small delay. Otherwise, some old asyncio versions do not transmit CLOSE frame,
# despite promising to do so.
DISCONNECT_AFTER_ERROR_DELAY = 0.01


cdef:
    set _ALLOWED_CLOSE_CODES = {int(i) for i in WSCloseCode}
    bytes _WS_KEY = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


cdef extern from "picows_compat.h" nogil:
    cdef int PLATFORM_IS_APPLE
    cdef int PLATFORM_IS_LINUX
    cdef int PLATFORM_IS_WINDOWS

    uint32_t ntohl(uint32_t)
    uint32_t htonl(uint32_t)
    uint16_t ntohs(uint16_t)
    uint16_t htons(uint16_t)

    uint64_t be64toh(uint64_t)
    uint64_t htobe64(uint64_t)

    cdef ssize_t PICOWS_SOCKET_ERROR
    double picows_get_monotonic_time()
    ssize_t send(int sockfd, const void* buf, size_t len, int flags)

    ctypedef size_t(*apply_mask_fn)(uint8_t*, size_t, size_t, uint32_t)

    size_t rotate_right(uint32_t value, size_t num_bytes)
    size_t mask_misaligned_bytes_at_front(uint8_t* input, size_t input_len, uint32_t mask, size_t alignment)
    size_t apply_mask_4(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask)
    size_t apply_mask_1(uint8_t* input, size_t input_len, size_t start_pos, uint32_t mask)
    apply_mask_fn get_apply_mask_fast_fn()
    size_t get_apply_mask_fast_alignment()


cdef:
    apply_mask_fn apply_mask_fast = get_apply_mask_fast_fn()
    size_t apply_mask_fast_alignment = get_apply_mask_fast_alignment()


cdef void _mask_payload(uint8_t* input, size_t input_len, uint32_t mask) noexcept:
    cdef size_t curr_pos = mask_misaligned_bytes_at_front(input, input_len, mask, apply_mask_fast_alignment)
    cdef size_t rotated_mask = rotate_right(mask, curr_pos)

    if curr_pos < input_len:
        curr_pos = apply_mask_fast(input, input_len, curr_pos, rotated_mask)

    if curr_pos < input_len:
        curr_pos = apply_mask_4(input, input_len, curr_pos, rotated_mask)

    if curr_pos < input_len:
        apply_mask_1(input, input_len, curr_pos, rotated_mask)


cdef _unpack_bytes_like(object bytes_like_obj, char** msg_ptr_out, Py_ssize_t* msg_size_out):
    cdef Py_buffer msg_buffer

    if PyBytes_CheckExact(bytes_like_obj):
        msg_ptr_out[0] = PyBytes_AS_STRING(bytes_like_obj)
        msg_size_out[0] = PyBytes_GET_SIZE(bytes_like_obj)
    elif PyByteArray_CheckExact(bytes_like_obj):
        msg_ptr_out[0] = PyByteArray_AS_STRING(bytes_like_obj)
        msg_size_out[0] = PyByteArray_GET_SIZE(bytes_like_obj)
    elif bytes_like_obj is None:
        msg_ptr_out[0] = NULL
        msg_size_out[0] = 0
    else:
        PyObject_GetBuffer(bytes_like_obj, &msg_buffer, PyBUF_SIMPLE)
        msg_ptr_out[0] = <char*>msg_buffer.buf
        msg_size_out[0] = msg_buffer.len
        # We can already release because we still keep the reference to the message
        PyBuffer_Release(&msg_buffer)


@cython.no_gc
@cython.freelist(64)
cdef class WSFrame:
    """
    Received websocket frame.

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
        return PyBytes_FromStringAndSize(self.payload_ptr, self.payload_size)

    cpdef str get_payload_as_utf8_text(self):
        """
        :return: a new str object with a copy of frame payload.
        
        This method will throw if payload does not contain valid UTF8 text.
        
        This method does not cache results. Payload is copied and a new str object is created every time this method is called.
        """
        return PyUnicode_FromStringAndSize(self.payload_ptr, self.payload_size)

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
                f"rsv1={True if self.rsv1 else False}, "
                f"last_in_buffer={True if self.last_in_buffer else False}, "
                f"payload_sz={self.payload_size}, tail_sz={self.tail_size})")


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

    cdef _reserve(self, Py_ssize_t target_size):
        cdef Py_ssize_t new_capacity = 256 * (target_size / 256 + 1)
        cdef char* data = <char*>PyMem_Realloc(self.data, new_capacity)
        if data == NULL:
            raise MemoryError("cannot allocate memory for picows")
        self.data = data
        self.capacity = new_capacity

    cdef resize(self, Py_ssize_t new_size):
        if new_size > self.capacity:
            self._reserve(new_size)
        self.size = new_size


cdef class WSListener:
    """
    Base class for user handlers.

    All `on_ws_*` methods receive `transport` as a first argument for convenience. It is guaranteed that passed
    `transport` object is always the same for the same connection.
    """

    cpdef on_ws_connected(self, WSTransport transport):
        """        
        Called after websocket handshake is complete and websocket is ready to send and receive frames.
        Initiate disconnect if exception is thrown by user handler.
        
        * client side: the exception will be transferred to and reraised by :any:`wait_disconnected`.
        * server side: the exception will be 'swallowed' by the library and logged at the ERROR level.

        :param transport: :any:`WSTransport` object      
        """
        pass

    cpdef on_ws_frame(self, WSTransport transport, WSFrame frame):
        """
        Called when a new frame is received.
        
        Initiate disconnect if exception is thrown by user handler and
        `disconnect_on_exception` was set to True in :any:`ws_connect` 
        or :any:`ws_create_server`.
        In such case:
         
        * client side: the exception will be transferred to and reraised by :any:`wait_disconnected`.
        * server side: the exception will be 'swallowed' by the library and logged at the ERROR level.
         
        .. DANGER::
            WSFrame is essentially just a pointer to a chunk of memory in the receiving buffer. It does not own 
            the memory. Do NOT cache or store WSFrame object for later processing because the data may be invalidated
            after :any:`WSListener.on_ws_frame` is complete.
            Process the payload immediately or just copy it with one of `WSFrame.get_*` methods.            

        :param transport: :any:`WSTransport` object
        :param frame: :any:`WSFrame` object            
        """
        pass

    cpdef on_ws_disconnected(self, WSTransport transport):
        """
        Called when websocket has been disconnected.

        :param transport: :any:`WSTransport`        
        """
        pass

    cpdef send_user_specific_ping(self, WSTransport transport):
        """
        Called when the auto-ping logic wants to send a ping to a remote peer.
        
        User can override this method to send something else instead of 
        the standard PING frame.
        
        Default implementation:
        
        .. code:: python
        
            def send_user_specific_ping(self, transport: picows.WSTransport)
                return transport.send_ping()

        :param transport: :any:`WSTransport`
        """
        transport.send_ping()

    cpdef is_user_specific_pong(self, WSFrame frame):
        """        
        Called before :any:`WSListener.on_ws_frame` if auto ping is enabled and pong is expected. 
        
        User can override this method to indicate that the received frame is a 
        valid response to a previously sent user specific ping message.
        
        The default implementation just do:
        
        .. code:: python
        
            def is_user_specific_pong(self, frame: picows.WSFrame)
                return frame.msg_type == WSMsgType.PONG
        
        :return: Returns True if the frame is a response to a previously send ping. In such case the frame will be  *consumed* by the protocol, i.e :any:`WSListener.on_ws_frame` will not be called for this frame.         
        """
        return frame.msg_type == WSMsgType.PONG

    cpdef pause_writing(self):
        """
        Called when the underlying transport’s buffer goes over the high watermark.
        This is a purely informative callback. You can ignore it and just keep writing.
        The data will be queued and eventually send anyway.
        """
        pass

    cpdef resume_writing(self):
        """
        Called when the underlying transport’s buffer drains below the low watermark.
        """
        pass


cdef class WSTransport:
    def __init__(self, bint is_client_side, underlying_transport, logger, loop):
        self.underlying_transport = underlying_transport
        self.is_client_side = is_client_side
        self.is_secure = underlying_transport.get_extra_info('ssl_object') is not None
        self.is_close_frame_sent = False
        self.request = None
        self.response = None #
        self.auto_ping_expect_pong = False
        self.pong_received_at_future = None
        self.listener_proxy = None
        self.disconnected_future = loop.create_future()
        self._loop = loop
        self._logger = logger
        self._log_debug_enabled = self._logger.isEnabledFor(PICOWS_DEBUG_LL)
        self._write_buf = MemoryBuffer(1024)
        self._socket = underlying_transport.get_extra_info('socket').fileno()

    cdef send_reuse_external_buffer(self, WSMsgType msg_type,
                                    char* msg_ptr, Py_ssize_t msg_size,
                                    bint fin=True, bint rsv1=False):
        if self.is_close_frame_sent:
            self._logger.debug("Ignore attempt to send a message after WSMsgType.CLOSE has already been sent")
            return

        cdef:
            uint8_t* header_ptr = <uint8_t*>msg_ptr
            uint64_t extended_payload_length_64
            uint32_t mask = 0
            uint16_t extended_payload_length_16
            uint8_t first_byte = <uint8_t>msg_type
            uint8_t second_byte = 0
            Py_ssize_t total_size = msg_size

        if self.is_client_side:
            mask = <uint32_t> rand()
            second_byte = 0x80
            total_size += 4
            header_ptr -= 4
            (<uint32_t*>header_ptr)[0] = mask

        if fin:
            first_byte |= 0x80

        if rsv1:
            first_byte |= 0x40

        if msg_size < 126:
            total_size += 2
            header_ptr -= 2
            header_ptr[0] = first_byte
            header_ptr[1] = second_byte | <uint8_t>msg_size
        elif msg_size < (1 << 16):
            total_size += 4
            header_ptr -= 4
            header_ptr[0] = first_byte
            header_ptr[1] = second_byte | 126
            extended_payload_length_16 = htons(<uint16_t>msg_size)
            (<uint16_t*>(header_ptr + 2))[0] = extended_payload_length_16
        else:
            total_size += 10
            header_ptr -= 10
            header_ptr[0] = first_byte
            header_ptr[1] = second_byte | 127
            extended_payload_length_64 = htobe64(<uint64_t>msg_size)
            (<uint64_t*> (header_ptr + 2))[0] = extended_payload_length_64

        if self.is_client_side:
            _mask_payload(<uint8_t*>msg_ptr, msg_size, mask)

        if self.is_secure:
            self.underlying_transport.write(PyBytes_FromStringAndSize(<char*>header_ptr, total_size))
        else:
            self._try_native_write_then_transport_write(<char*>header_ptr, total_size)

        if msg_type == WSMsgType.CLOSE:
            self.is_close_frame_sent = True

    cpdef send_reuse_external_bytearray(self, WSMsgType msg_type,
                                        bytearray buffer,
                                        Py_ssize_t msg_offset,
                                        bint fin=True, bint rsv1=False):
        """
        Send a frame over websocket with a message as its payload. 
        This function does not copy message to prepare websocket frames. 
        It reuses bytearray's memory to write websocket frame header at the front.
        
        :param msg_type: :any:`WSMsgType` enum value\n 
        :param msg_offset: specifies where message begins in the bytearray. 
            Must be at least 14 to let picows to write websocket frame header in front of the message.
        :param buffer: bytearray that contains message and some extra space (at least 14 bytes) in the beginning.
            The len of the message is determined as `len(buffer) - msg_offset`         
        :param fin: fin bit in websocket frame.
            Indicate that the frame is the last one in the message.
        :param rsv1: first reserved bit in websocket frame. 
            Some protocol extensions use it to indicate that payload is compressed.        
        """
        assert buffer is not None, "buffer is None"
        assert msg_offset >= 14, "buffer must have at least 14 bytes available before message starts, check msg_offset parameter"

        cdef:
            char* buffer_ptr = PyByteArray_AS_STRING(buffer)
            Py_ssize_t buffer_size = PyByteArray_GET_SIZE(buffer)

        assert buffer_size >= msg_offset, "msg_offset points beyond buffer end, msg_offset > len(buffer)"

        cdef:
            char* msg_ptr = buffer_ptr + msg_offset
            Py_ssize_t msg_size = buffer_size - msg_offset

        self.send_reuse_external_buffer(msg_type, msg_ptr, msg_size, fin, rsv1)

    cpdef send(self, WSMsgType msg_type, message, bint fin=True, bint rsv1=False):
        """        
        Send a frame over websocket with a message as its payload.
        
        Please note that this function has to copy the whole message into 
        library's write buffer in order to be able to prepend websocket 
        frame header and apply mask to the whole message. If you want to avoid 
        copying please use :any:`WSTransport.send_reuse_external_bytearray` or 
        :any:`WSTransport.send_reuse_external_buffer`.

        :param msg_type: :any:`WSMsgType` enum value\n 
        :param message: an optional bytes-like object
        :param fin: fin bit in websocket frame.
            Indicate that the frame is the last one in the message.
        :param rsv1: first reserved bit in websocket frame. 
            Some protocol extensions use it to indicate that payload 
            is compressed.        
        """
        cdef:
            char* msg_ptr
            Py_ssize_t msg_length

        _unpack_bytes_like(message, &msg_ptr, &msg_length)

        # We can potentially do better here by combining memcpy memory traversal
        # with masking. Still people who wants maximum performance should use
        # send_reuse_external_bytearray instead of send to avoid memory copying
        # at all
        self._write_buf.resize(msg_length + 16)
        memcpy(self._write_buf.data + 16, msg_ptr, msg_length)

        self.send_reuse_external_buffer(msg_type, self._write_buf.data + 16, msg_length, fin, rsv1)

    cpdef send_ping(self, message=None):
        """
        Send a PING control frame with an optional message.
        
        :param message: an optional bytes-like object
        """
        self.send(WSMsgType.PING, message)

    cpdef send_pong(self, message=None):
        """
        Send a PONG control frame with an optional message.

        :param message: an optional bytes-like object
        """
        self.send(WSMsgType.PONG, message)

    cpdef send_close(self, WSCloseCode close_code=WSCloseCode.NO_INFO, close_message=None):
        """
        Send a CLOSE control frame with an optional message.
        This method doesn't disconnect the underlying transport.
        Does nothing if the underlying transport is already disconnected.        
        
        :param close_code: :any:`WSCloseCode` value                
        :param close_message: an optional bytes-like object        
        """
        if self.underlying_transport.is_closing():
            return

        cdef:
            char* msg_ptr
            Py_ssize_t msg_length

        _unpack_bytes_like(close_message, &msg_ptr, &msg_length)

        self._write_buf.resize(msg_length + 2 + 16)
        (<uint16_t*>(self._write_buf.data + 16))[0] = htons(<uint16_t>close_code)
        memcpy(self._write_buf.data + 2 + 16, msg_ptr, msg_length)

        self.send_reuse_external_buffer(WSMsgType.CLOSE, self._write_buf.data + 16, msg_length + 2, True, False)

    cpdef disconnect(self, bint graceful=True):
        """
        Close the underlying transport.

        It is safe to call this method multiple times. 
        It does nothing if the transport is already closed.

        :param graceful: If True then send any remaining outgoing data in the buffer before closing the socket. This may potentially significantly delay on_ws_disconnected event since OS may wait for TCP_ACK for the data that was previously sent and until OS ack timeout fires up the socket will remain in connected state.           
        """
        if graceful:
            self.underlying_transport.close()
        else:
            self.underlying_transport.abort()

    async def wait_disconnected(self):
        """
        Wait until websocket is fully disconnected.

        Completion means:

        * the underlying transport is closed
        * :any:`WSListener.on_ws_disconnected` callback has finished

        Exception behavior:

        * client side: if disconnect was initiated because user callback raised,
          the original exception is transferred here and re-raised by this
          coroutine when awaited.
        * client side: websocket/protocol failures may also be re-raised here
          (for example :any:`WSError`).
        * server side: always completes normally (no per-client exception
          propagation via this coroutine).

        This coroutine internally shields the wait future, so cancelling the
        waiter does not cancel internal disconnect bookkeeping.

        """
        await asyncio.shield(self.disconnected_future)

    async def measure_roundtrip_time(self, int rounds) -> list[float]:
        """
        Coroutine that measures roundtrip time by running ping-pong.

        :param rounds: how many ping-pong rounds to do
        :return: list of measured roundtrip times
        """

        cdef double ping_at
        cdef double pong_at
        cdef int i
        cdef list results = []
        cdef object shield = asyncio.shield
        cdef object create_future = self._loop.create_future

        # If auto-ping is enabled and currently waiting for pong then
        # wait until we receive it and only then proceed with our own pings
        if self.auto_ping_expect_pong:
            self.pong_received_at_future = create_future()
            await shield(self.pong_received_at_future)

        for i in range(rounds):
            self.listener_proxy.send_user_specific_ping(self)
            self.pong_received_at_future = create_future()
            ping_at = picows_get_monotonic_time()
            pong_at = await shield(self.pong_received_at_future)
            results.append(pong_at - ping_at)

        return results

    cpdef notify_user_specific_pong_received(self):
        """
        Notify the auto-ping loop that a user-specific pong message 
        has been received.
        
        This method is useful when determining whether a frame contains a 
        user-specific pong is too expensive for is_user_specific_pong 
        (for example, it may require full JSON parsing). 
        In such cases, :any:`WSListener.is_user_specific_pong` should always 
        return `False`, and the logic in :any:`WSListener.on_ws_frame` should 
        call :any:`WSTransport.notify_user_specific_pong_received`.
        
        It is safe to call this method even if auto-ping is disabled or 
        the auto-ping loop doesn’t expect pong messages. 
        In such cases, the method simply does nothing.
        """
        self.auto_ping_expect_pong = False

        if self.pong_received_at_future is not None:
            self.pong_received_at_future.set_result(picows_get_monotonic_time())
            self.pong_received_at_future = None

            if self._log_debug_enabled:
                self._logger.log(PICOWS_DEBUG_LL,
                                 "notify_user_specific_pong_received() for PONG(measure_roundtrip_time), reset expect_pong")
        else:
            if self._log_debug_enabled:
                self._logger.log(PICOWS_DEBUG_LL,
                                 "notify_user_specific_pong_received() for PONG(idle timeout), reset expect_pong")

    cdef _send_http_handshake(self, bytes ws_path, bytes host_port, bytes websocket_key_b64, object extra_headers):

        request = WSUpgradeRequest()
        request.method = b"GET"
        request.path = ws_path
        request.version = b"HTTP/1.1"
        request.headers = CIMultiDict([
            ("Host", host_port.decode()),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", websocket_key_b64.decode()),
        ])
        add_extra_headers(request.headers, extra_headers)

        headers = "\r\n".join(f"{k}: {v}" for k, v in request.headers.items()).encode()

        initial_handshake = (b"%b %b %b\r\n"
                             b"%b\r\n"
                             b"\r\n" % (request.method, request.path, request.version, headers))

        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "Send upgrade request: %s", initial_handshake)
        self.request = request
        self.underlying_transport.write(initial_handshake)

    cdef _send_http_handshake_response(self, response, bytes accept_val):
        if accept_val is not None:
            response.headers["Sec-WebSocket-Accept"] = accept_val.decode()

        cdef bytearray response_bytes = response.to_bytes()

        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "Send upgrade response: %s", response_bytes)
        self.response = response
        self.underlying_transport.write(response_bytes)

    cdef _try_native_write_then_transport_write(self, char* ptr, Py_ssize_t sz):
        if <Py_ssize_t>self.underlying_transport.get_write_buffer_size() > 0:
            self.underlying_transport.write(PyBytes_FromStringAndSize(ptr, sz))
            return

        cdef Py_ssize_t bytes_written = send(self._socket, ptr, <size_t>sz, 0)

        # From libuv code (unix/stream.c):
        #   Due to a possible kernel bug at least in OS X 10.10 "Yosemite",
        #   EPROTOTYPE can be returned while trying to write to a socket
        #   that is shutting down. If we retry the write, we should get
        #   the expected EPIPE instead.

        while (bytes_written == PICOWS_SOCKET_ERROR and
               ((not PLATFORM_IS_WINDOWS and errno.errno == errno.EINTR) or
                (PLATFORM_IS_APPLE and errno.errno == errno.EPROTOTYPE))):
            bytes_written = send(self._socket, self._write_buf.data, sz, 0)

        if bytes_written == sz:
            return
        elif bytes_written >= 0:
            self.underlying_transport.write(PyBytes_FromStringAndSize(<char*> ptr + bytes_written, sz - bytes_written))
            return

        # In case of errors we ask asyncio to try sending again.
        # Asyncio will try and based on error code may report 'disconnected' event.
        self.underlying_transport.write(PyBytes_FromStringAndSize(<char *> ptr, sz))


cdef class WSProtocol:
    cdef:
        readonly WSTransport transport
        readonly WSListener listener

        object _listener_factory
        bytes _host_port
        bytes _ws_path
        object _logger                          #: Logger
        bint _log_debug_enabled
        bint is_client_side
        bint _disconnect_on_exception
        object _disconnect_exception            #: Optional[Exception]

        object _loop

        object _handshake_timeout
        object _handshake_timeout_handle
        object _handshake_complete_future
        Py_ssize_t _upgrade_request_max_size

        bytes _websocket_key_b64
        Py_ssize_t _max_frame_size

        bint _enable_auto_pong
        bint _enable_auto_ping
        double _auto_ping_idle_timeout
        double _auto_ping_reply_timeout
        WSAutoPingStrategy _auto_ping_strategy
        object _auto_ping_loop_task
        double _last_data_time

        object _extra_headers

        # The following are the parts of an unfinished frame
        # Once the frame is finished WSFrame is created and returned
        WSParserState _state
        MemoryBuffer _buffer
        Py_ssize_t _f_new_data_start_pos
        Py_ssize_t _f_curr_state_start_pos
        Py_ssize_t _f_curr_frame_start_pos
        Py_ssize_t _f_payload_length
        Py_ssize_t _f_payload_start_pos
        WSMsgType _f_msg_type
        uint32_t _f_mask
        uint8_t _f_fin
        uint8_t _f_rsv1
        uint8_t _f_has_mask
        uint8_t _f_payload_length_flag

    def __init__(self,
                 str host_port,
                 str ws_path,
                 bint is_client_side,
                 ws_listener_factory,
                 logger,
                 bint disconnect_on_exception,
                 websocket_handshake_timeout,
                 enable_auto_ping, auto_ping_idle_timeout, auto_ping_reply_timeout,
                 auto_ping_strategy,
                 enable_auto_pong,
                 max_frame_size,
                 extra_headers):
        self.transport = None
        self.listener = None

        self._listener_factory = ws_listener_factory
        self._host_port = host_port.encode() if host_port is not None else None
        self._ws_path = ws_path.encode() if ws_path else b"/"
        self._logger = logger
        self._log_debug_enabled = self._logger.isEnabledFor(PICOWS_DEBUG_LL)
        self.is_client_side = is_client_side
        self._disconnect_on_exception = disconnect_on_exception
        self._disconnect_exception = None

        self._loop = asyncio.get_running_loop()

        self._handshake_timeout = websocket_handshake_timeout
        self._handshake_timeout_handle = None
        self._handshake_complete_future = self._loop.create_future()
        self._upgrade_request_max_size = 16 * 1024

        self._websocket_key_b64 = b64encode(os.urandom(16))
        self._max_frame_size = max_frame_size

        self._enable_auto_pong = enable_auto_pong
        self._enable_auto_ping = enable_auto_ping
        self._auto_ping_idle_timeout = auto_ping_idle_timeout
        self._auto_ping_reply_timeout = auto_ping_reply_timeout
        self._auto_ping_strategy = auto_ping_strategy
        self._auto_ping_loop_task = None
        self._last_data_time = 0

        self._extra_headers = extra_headers

        if self._enable_auto_ping:
            assert self._auto_ping_reply_timeout <= self._auto_ping_idle_timeout, \
                "auto_ping_reply_timeout can't be bigger than auto_ping_idle_timeout"

        self._extra_headers = extra_headers

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
        self._f_rsv1 = 0
        self._f_has_mask = 0
        self._f_payload_length_flag = 0

    def connection_made(self, transport: asyncio.Transport):
        sock = transport.get_extra_info('socket')
        peername = transport.get_extra_info('peername')
        sockname = transport.get_extra_info('sockname')

        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if hasattr(socket, "TCP_QUICKACK"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)

        # self._logger.getLogger adds child logger to the global loggers dict.
        # These child loggers never get deleted after connections are lost
        # Therefore do not use getLogger, create and setup child loggers manually
        child_logger = logging.Logger(f"{self._logger.name}.{sock.fileno()}", logging.NOTSET)
        child_logger.parent = self._logger
        child_logger.propagate = True
        self._logger = child_logger

        quickack = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK) if hasattr(socket, "TCP_QUICKACK") else False

        if self.is_client_side:
            self._logger.info("WS connection established: %s -> %s, recvbuf=%d, sendbuf=%d, quickack=%d, nodelay=%d",
                              sockname, peername,
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                              quickack,
                              sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
        else:
            self._logger.info("New connection accepted: %s <- %s, recvbuf=%d, sendbuf=%d, quickack=%d, nodelay=%d",
                              sockname, peername,
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                              sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                              quickack,
                              sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))


        self.transport = WSTransport(self.is_client_side, transport, self._logger, self._loop)

        if self.is_client_side:
            self.transport._send_http_handshake(self._ws_path, self._host_port, self._websocket_key_b64, self._extra_headers)
            self._handshake_timeout_handle = self._loop.call_later(
                self._handshake_timeout, self._handshake_timeout_callback)
        else:
            self._handshake_timeout_handle = self._loop.call_later(
                self._handshake_timeout, self._handshake_timeout_callback)

    def connection_lost(self, exc):
        self._logger.info("Disconnected")

        if self._handshake_complete_future.done():
            if self._handshake_complete_future.exception() is None:
                self._invoke_on_ws_disconnected()
        else:
            self._handshake_complete_future.set_result(None)

        if self._handshake_timeout_handle is not None:
            self._handshake_timeout_handle.cancel()

        if self._auto_ping_loop_task is not None and not self._auto_ping_loop_task.done():
            self._auto_ping_loop_task.cancel()

        if self.transport.pong_received_at_future is not None:
            self.transport.pong_received_at_future.set_exception(ConnectionResetError())
            self.transport.pong_received_at_future = None

        if not self.transport.disconnected_future.done():
            # The server side does not allow to await on a particular client or retrieve its disconnect exception.
            # Do not set exception on future to avoid warnings about unconsumed exception from asyncio.
            if self._disconnect_exception is None or not self.is_client_side:
                self.transport.disconnected_future.set_result(None)
            else:
                self.transport.disconnected_future.set_exception(self._disconnect_exception)

    def eof_received(self) -> bool:
        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "EOF marker received")
        # Returning False here means that the transport should close itself
        return False

    def pause_writing(self):
        self._logger.warning("Protocol writing pause requested, crossed writing buffer high-watermark")
        if self.listener is not None:
            self.listener.pause_writing()

    def resume_writing(self):
        self._logger.warning("Protocol writing resume requested, crossed writing buffer low-watermark,")
        if self.listener is not None:
            self.listener.resume_writing()

    # uvloop and asyncio use different checks to detect BufferedProtocol
    #
    # uvloop looks at the presence of get_buffer attribute and check that
    # user type is not derived from asyncio.Protocol.
    #
    # asyncio expect user protocol to actually derive from asyncio.BufferedProtocol.
    # Unfortunately Cython extension types are not allowed to derive pure python types.
    # It is possible make a pure python wrapper around cython type but this will result in
    # extra dictionary lookup everytime get_buffer, buffer_updated are called
    #
    # So for the time being I implemented both data_received, and (get_buffer, buffer_updated).
    # uvloop will use (get_buffer, buffer_updated) and asyncio will use data_received
    def data_received(self, data):
        cdef:
            char* ptr
            Py_ssize_t sz

        _unpack_bytes_like(data, &ptr, &sz)

        # Leave some space for simd parsers like simdjson, they require extra
        # space beyond normal data to make sure that vector reads
        # don't cause access violation
        if self._buffer.size - self._f_new_data_start_pos < (sz + 64):
            self._buffer.resize(self._f_new_data_start_pos + sz + 64)

        memcpy(self._buffer.data + self._f_new_data_start_pos, ptr, sz)
        self._f_new_data_start_pos += sz

        self._process_new_data()

    def get_buffer(self, Py_ssize_t size_hint):
        cdef Py_ssize_t sz = size_hint + 1024
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
        self._process_new_data()

    async def wait_until_handshake_complete(self):
        await asyncio.shield(self._handshake_complete_future)

    cdef inline _process_new_data(self):
        if self._state == WSParserState.WAIT_UPGRADE_RESPONSE:
            if not self._negotiate():
                return

        self._last_data_time = picows_get_monotonic_time()

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

    cdef inline _negotiate(self):
        response = None

        if self.is_client_side:
            try:
                response = self._try_read_and_process_upgrade_response()
                if self._state == WSParserState.WAIT_UPGRADE_RESPONSE:
                    # Upgrade response hasn't fully arrived yet
                    return False
                self.listener = self._listener_factory()
                self.transport.listener_proxy = weakref.proxy(self.listener)
                self.transport.response = response
                self._listener_factory = None
            except Exception as ex:
                self.transport.disconnect()
                self._handshake_complete_future.set_exception(ex)
                return False
        else:
            try:
                upgrade_request, accept_val = self._try_read_upgrade_request()
            except RuntimeError as ex:
                response = WSUpgradeResponse.create_error_response(
                    HTTPStatus.BAD_REQUEST, str(ex).encode())

                self.transport._send_http_handshake_response(response, None)
                self.transport.disconnect()
                return False

            if accept_val is None:
                # Upgrade request hasn't fully arrived yet
                return False

            listener_factory = self._listener_factory
            self._listener_factory = None
            try:
                listener_or_response_with_listener = listener_factory(upgrade_request)
                if isinstance(listener_or_response_with_listener, WSUpgradeResponseWithListener):
                    self.listener = listener_or_response_with_listener.listener
                    response = listener_or_response_with_listener.response
                elif isinstance(listener_or_response_with_listener, WSListener):
                    self.listener = listener_or_response_with_listener
                    response = WSUpgradeResponse.create_101_response()
                elif listener_or_response_with_listener is None:
                    self.listener = None
                    response = WSUpgradeResponse.create_error_response(
                        HTTPStatus.NOT_FOUND, b"404 Not Found"
                    )
                else:
                    raise TypeError("user listener_factory returned wrong listener type")

                if self.listener is not None:
                    self.transport.listener_proxy = weakref.proxy(self.listener)
            except Exception as ex:
                response = WSUpgradeResponse.create_error_response(
                    HTTPStatus.INTERNAL_SERVER_ERROR, str(ex).encode())
                self.transport._send_http_handshake_response(response, None)
                self.transport.disconnect()
                return False

            if response.status != HTTPStatus.SWITCHING_PROTOCOLS:
                self.transport._send_http_handshake_response(response, None)
                self.transport.disconnect()
                return False
            else:
                self.transport._send_http_handshake_response(response, accept_val)

        self._handshake_timeout_handle.cancel()
        self._handshake_timeout_handle = None
        self._handshake_complete_future.set_result(None)
        self._invoke_on_ws_connected()
        self._last_data_time = picows_get_monotonic_time()
        if self._enable_auto_ping:
            self._auto_ping_loop_task = self._loop.create_task(self._auto_ping_loop())
        return True

    async def _auto_ping_loop(self):
        cdef double now
        cdef double prev_last_data_time
        cdef double idle_delay
        cdef object sleep = asyncio.sleep
        try:
            if self._log_debug_enabled:
                self._logger.log(PICOWS_DEBUG_LL, "Auto-ping loop started with idle_timeout=%s, reply_timeout=%s",
                                 self._auto_ping_idle_timeout, self._auto_ping_reply_timeout)

            while True:
                if self._auto_ping_strategy == WSAutoPingStrategy.PING_WHEN_IDLE:
                    now = picows_get_monotonic_time()
                    idle_delay = self._last_data_time + self._auto_ping_idle_timeout - now
                    prev_last_data_time = self._last_data_time
                    await sleep(idle_delay)

                    if self._last_data_time > prev_last_data_time:
                        continue

                    if self._log_debug_enabled:
                        self._logger.log(PICOWS_DEBUG_LL, "Send PING because no new data over the last %s seconds", self._auto_ping_idle_timeout)
                else:
                    await sleep(self._auto_ping_idle_timeout)

                    if self._log_debug_enabled:
                        self._logger.log(PICOWS_DEBUG_LL, "Send periodic PING")

                if self.transport.pong_received_at_future is not None:
                    # measure_roundtrip_time is currently doing it's own ping-pongs
                    # set _last_data_time to now and sleep
                    self._last_data_time = picows_get_monotonic_time()
                    if self._log_debug_enabled:
                        self._logger.log(PICOWS_DEBUG_LL, "Hold back PING sending, because measure_roundtrip_time is in progress")

                    continue

                self.listener.send_user_specific_ping(self.transport)

                self.transport.auto_ping_expect_pong = True
                await sleep(self._auto_ping_reply_timeout)
                if self.transport.auto_ping_expect_pong:
                    # Pong hasn't arrived within specified interval
                    self._logger.info(
                        "Initiating disconnect because no PONG was received within %s seconds",
                        self._auto_ping_reply_timeout)

                    self.transport.send_close(WSCloseCode.GOING_AWAY, f"peer has not replied to ping/heartbeat request within {self._auto_ping_reply_timeout} second(s)".encode())
                    # Give a chance for the transport to send close message
                    # But don't wait for any tcp confirmation, use abort()
                    # because normal disconnect may hang until OS TCP/IP timeout
                    # for ACK is fired.
                    self._loop.call_later(DISCONNECT_AFTER_ERROR_DELAY, self.transport.underlying_transport.abort)
                    break
        except asyncio.CancelledError:
            if self._log_debug_enabled:
                self._logger.log(PICOWS_DEBUG_LL, "Auto-ping loop cancelled")
        except:
            self._logger.exception("Auto-ping loop failed, disconnect websocket")
            self.transport.send_close(WSCloseCode.INTERNAL_ERROR, b"an exception occurred in auto-ping loop")
            self._loop.call_later(DISCONNECT_AFTER_ERROR_DELAY, self.transport.disconnect)

    cdef inline tuple _try_read_upgrade_request(self):
        cdef bytes data = PyBytes_FromStringAndSize(self._buffer.data, self._f_new_data_start_pos)
        cdef list request = <list>data.split(b"\r\n\r\n", 1)
        if len(request) < 2:
            if len(data) >= self._upgrade_request_max_size:
                self.transport.disconnect()
                self._logger.info("Disconnect because upgrade request violated max_size threshold: %d", 16*1024)

            return None, None

        cdef bytes raw_headers = <bytes>request[0]
        if len(raw_headers) >= self._upgrade_request_max_size:
            self.transport.disconnect()
            self._logger.info("Disconnect because upgrade request violated max_size threshold: %d", 16*1024)
            return None, None

        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "New data: %s", data)

        cdef list lines = <list>raw_headers.split(b"\r\n")
        cdef bytes response_status_line = <bytes>lines[0]

        cdef object headers = CIMultiDict()
        cdef list parts
        cdef bytes line, name, value
        cdef str name_str
        cdef Py_ssize_t idx
        for idx in range(1, len(lines)):
            line = <bytes>lines[idx]
            parts = <list>line.split(b":", 1)
            if len(parts) != 2:
                raise RuntimeError(f"Mailformed header in upgrade request: {raw_headers}")
            name, value = <bytes>parts[0], <bytes>parts[1]
            headers.add((<bytes>name.strip()).decode(), (<bytes>value.strip()).decode())

        if "websocket" != headers.get("upgrade"):
            raise RuntimeError(f"No WebSocket UPGRADE header: {raw_headers}\n Can 'Upgrade' only to 'websocket'")

        if "connection" not in headers:
            raise RuntimeError(f"No CONNECTION upgrade header: {raw_headers}\n")

        if "upgrade" != headers["connection"].lower():
            raise RuntimeError(f"CONNECTION header value is not 'upgrade' : {raw_headers}\n")

        version = headers.get("sec-websocket-version")
        if headers.get("sec-websocket-version") not in ("13", "8", "7"):
            raise RuntimeError(f"Upgrade requested to unsupported websocket version: {version}")

        cdef str key = <str>headers.get("sec-websocket-key")
        try:
            if not key or len(b64decode(key)) != 16:
                raise RuntimeError(f"Handshake error, invalid key: {key!r}")
        except binascii.Error:
            raise RuntimeError(f"Handshake error, invalid key: {key!r}") from None

        cdef bytes accept_val = b64encode(sha1(<bytes>key.encode() + _WS_KEY).digest())

        cdef list status_line_parts = response_status_line.split(b" ")
        upgrade_request = WSUpgradeRequest()
        upgrade_request.method = <bytes>status_line_parts[0]
        upgrade_request.path = <bytes>status_line_parts[1]
        upgrade_request.version = <bytes>status_line_parts[2]
        upgrade_request.headers = headers

        memmove(self._buffer.data, self._buffer.data + len(raw_headers) + 4, self._buffer.size - len(raw_headers) - 4)

        cdef bytes tail = request[1]
        self._f_new_data_start_pos = len(tail)
        self._state = WSParserState.READ_HEADER

        return upgrade_request, accept_val

    cdef inline object _try_read_and_process_upgrade_response(self):
        cdef bytes data = PyBytes_FromStringAndSize(self._buffer.data, self._f_new_data_start_pos)
        cdef list data_parts = <list>data.split(b"\r\n\r\n", 1)
        if len(data_parts) < 2:
            return None

        cdef bytes raw_headers, tail
        raw_headers, tail = <bytes>data_parts[0], <bytes>data_parts[1]

        cdef list lines = <list>raw_headers.split(b"\r\n")
        cdef bytes response_status_line = <bytes>lines[0]

        cdef str response_status_line_str = response_status_line.decode().lower()

        # check handshake
        if not response_status_line_str.startswith("http/1.1 " ):
            raise WSError(f"cannot upgrade, unknown protocol (expected HTTP/1.1) in upgrade response: {response_status_line_str}", raw_headers, tail)

        cdef bytes status_code
        response = WSUpgradeResponse()
        response.version, status_code, status_phrase = response_status_line.split(b" ", 2)
        response.status = HTTPStatus(int(status_code.decode()))

        cdef bytes line, name, value
        response.headers = CIMultiDict()
        for idx in range(1, len(lines)):
            line = <bytes>lines[idx]
            name, value = <list>line.split(b":", 1)
            response.headers.add((<bytes>name.strip()).decode(), (<bytes>value.strip()).decode())

        if response.status != HTTPStatus.SWITCHING_PROTOCOLS:
            raise WSError(f"expected upgrade response with status 101 Switching Protocols, but received {response.status}", raw_headers, tail, response)

        if response.headers.get("transfer-encoding") == "chunked":
            raise WSError(f"101 response cannot have Transfer-Encoding but it has", raw_headers, tail, response)

        cdef Py_ssize_t content_length = int(response.headers.get("content-length", "0"))

        if content_length != 0:
            raise WSError(f"101 response has non-zero Content-Length, but it can't have body", raw_headers, tail, response)

        connection_value = response.headers.get("connection")
        connection_value = connection_value if connection_value is None else connection_value.lower()
        if connection_value != "upgrade":
            raise WSError(f"cannot upgrade, invalid connection header: {response.headers['connection']}", raw_headers, tail, response)

        r_key = response.headers.get("sec-websocket-accept")
        match = b64encode(sha1(self._websocket_key_b64 + _WS_KEY).digest()).decode()
        if r_key != match:
            raise WSError(f"cannot upgrade, invalid sec-websocket-accept response", raw_headers, tail, response)

        memmove(self._buffer.data, self._buffer.data + len(raw_headers) + 4, self._buffer.size - len(raw_headers) - 4)
        self._f_new_data_start_pos = len(tail)
        self._state = WSParserState.READ_HEADER
        if self._log_debug_enabled:
            self._logger.log(PICOWS_DEBUG_LL, "WS handshake done, switch to upgraded state")

        return response

    cdef inline WSFrame _get_next_frame(self):
        cdef WSFrame frame
        try:
            return self._get_next_frame_impl()
        except _WSParserError as ex:
            self._logger.error("WS parser error: %s, initiate disconnect", ex.args)
            self._disconnect_exception = WSError(str(ex))
            self.transport.send_close(ex.args[0], ex.args[1].encode())
            self._loop.call_later(DISCONNECT_AFTER_ERROR_DELAY, self.transport.disconnect)
        except BaseException as ex:
            self._logger.exception("WS parser failure, initiate disconnect")
            self._disconnect_exception = WSError(str(ex))
            self.transport.send_close(WSCloseCode.PROTOCOL_ERROR)
            self._loop.call_later(DISCONNECT_AFTER_ERROR_DELAY, self.transport.disconnect)

    cdef inline WSFrame _get_next_frame_impl(self): #  -> Optional[WSFrame]
        """Return the next frame from the socket."""
        cdef:
            uint8_t first_byte
            uint8_t second_byte
            uint8_t rsv2, rsv3
            WSFrame frame

        if self._state == WSParserState.READ_HEADER:
            if self._f_new_data_start_pos - self._f_curr_state_start_pos < 2:
                return None

            first_byte = <uint8_t>self._buffer.data[self._f_curr_state_start_pos]
            second_byte = <uint8_t>self._buffer.data[self._f_curr_state_start_pos + 1]

            self._f_fin = (first_byte >> 7) & 1
            self._f_rsv1 = (first_byte >> 6) & 1
            rsv2 = (first_byte >> 5) & 1
            rsv3 = (first_byte >> 4) & 1
            self._f_msg_type = <WSMsgType>(first_byte & 0xF)

            # frame-fin = %x0 ; more frames of this message follow
            #           / %x1 ; final frame of this message
            # rsv1 is used by some extensions to indicate compressed frame
            # rsv2, rsv3 are not used, check and throw if they are set
            if rsv2 or rsv3:
                mem_dump = PyBytes_FromStringAndSize(
                    self._buffer.data + self._f_curr_state_start_pos,
                    max(self._f_new_data_start_pos - self._f_curr_state_start_pos, 64)
                )
                raise _WSParserError(
                    WSCloseCode.PROTOCOL_ERROR,
                    f"Received frame with non-zero reserved bits, rsv2={rsv2}, rsv3={rsv3}, msg_type={self._f_msg_type}: {mem_dump}",
                )

            if self._f_msg_type > 0x7 and not self._f_fin:
                raise _WSParserError(
                    WSCloseCode.PROTOCOL_ERROR,
                    "Received fragmented control frame",
                )

            self._f_has_mask = (second_byte >> 7) & 1
            self._f_payload_length_flag = second_byte & 0x7F

            if self._f_msg_type > 0x7 and self._f_payload_length_flag > 125:
                raise _WSParserError(
                    WSCloseCode.PROTOCOL_ERROR,
                    "Control frame payload cannot be larger than 125 bytes",
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
                raise _WSParserError(WSCloseCode.PROTOCOL_ERROR, f"Frame payload size violates max allowed size {self._f_payload_length} > {self._max_frame_size}")

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
            frame.rsv1 = self._f_rsv1
            frame.last_in_buffer = 0

            self._f_curr_state_start_pos += self._f_payload_length
            self._f_curr_frame_start_pos = self._f_curr_state_start_pos
            self._state = WSParserState.READ_HEADER

            if frame.msg_type == WSMsgType.CLOSE:
                if frame.get_close_code() < 3000 and frame.get_close_code() not in _ALLOWED_CLOSE_CODES:
                    raise _WSParserError(WSCloseCode.PROTOCOL_ERROR,
                                         f"Invalid close code: {frame.get_close_code()}")

                if frame.payload_size > 0 and frame.payload_size < 2:
                    raise _WSParserError(WSCloseCode.PROTOCOL_ERROR,
                                         f"Invalid close frame: {frame.fin} {frame.msg_type} {frame.get_payload_as_bytes()}")

            return frame

        assert False, "we should never reach this state"

    cdef inline _invoke_on_ws_connected(self):
        try:
            self.listener.on_ws_connected(self.transport)
        except Exception as exc:
            if self.is_client_side:
                self._logger.warning("Initiate disconnect because of exception from WSListener.on_ws_connected: %s", str(exc))
                self._disconnect_exception = exc
            else:
                self._logger.error("Initiate disconnect because of exception from WSListener.on_ws_connected: %s", str(exc))
            self.transport.send_close(WSCloseCode.INTERNAL_ERROR)
            self._loop.call_later(DISCONNECT_AFTER_ERROR_DELAY, self.transport.disconnect)

    cdef inline _invoke_on_ws_frame(self, WSFrame frame):
        try:
            if self._enable_auto_pong and frame.msg_type == WSMsgType.PING:
                payload = frame.get_payload_as_bytes()
                self.transport.send_pong(payload)
                if self._log_debug_enabled:
                    self._logger.log(PICOWS_DEBUG_LL, "PING(%s) frame received, replied with PONG", payload)
                return

            if self._enable_auto_ping and self.transport.auto_ping_expect_pong or self.transport.pong_received_at_future is not None:
                if self.listener.is_user_specific_pong(frame):
                    self.transport.auto_ping_expect_pong = False
                    if self.transport.pong_received_at_future is not None:
                        self.transport.pong_received_at_future.set_result(picows_get_monotonic_time())
                        self.transport.pong_received_at_future = None
                        if self._log_debug_enabled:
                            self._logger.log(PICOWS_DEBUG_LL, "Received PONG for the previously sent PING(measure_roundtrip_time), reset expect_pong flag")
                    else:
                        if self._log_debug_enabled:
                            self._logger.log(PICOWS_DEBUG_LL, "Received PONG for the previously sent PING(idle timeout), reset expect_pong flag")

                    return

            self.listener.on_ws_frame(self.transport, frame)
        except Exception as exc:
            if self._disconnect_on_exception:
                if self.is_client_side:
                    if self._disconnect_exception is None:
                        self._disconnect_exception = exc
                        self._logger.warning("Initiate disconnect because of exception from WSListener.on_ws_frame: %s", str(exc))
                    else:
                        self._logger.exception("Secondary exception from user's WSListener.on_ws_frame")
                else:
                    self._logger.exception("Initiate disconnect because of exception from WSListener.on_ws_frame")

                self.transport.send_close(WSCloseCode.INTERNAL_ERROR)
                self._loop.call_later(DISCONNECT_AFTER_ERROR_DELAY, self.transport.disconnect)
            else:
                self._logger.exception("Unhandled exception from user's WSListener.on_ws_frame")

    cdef inline _invoke_on_ws_disconnected(self):
        try:
            self.listener.on_ws_disconnected(self.transport)
        except Exception as exc:
            if self.is_client_side:
                if self._disconnect_exception is None:
                    self._disconnect_exception = exc
                    self._logger.warning("Exception from WSListener.on_ws_disconnected: %s", str(exc))
                else:
                    self._logger.error("Exception from WSListener.on_ws_disconnected: %s", str(exc))
            else:
                self._logger.exception("Unhandled exception from user's WSListener.on_ws_disconnected")

    cdef inline _shrink_buffer(self):
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
        if not self._handshake_complete_future.done():
            self._handshake_complete_future.set_exception(asyncio.TimeoutError("websocket handshake timeout"))
        self.transport.disconnect()
