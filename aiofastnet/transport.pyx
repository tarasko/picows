import collections
import os
import socket
import warnings
from asyncio.trsock import TransportSocket
from asyncio import BufferedProtocol
from logging import getLogger

from .system cimport *

from . import constants


cdef _logger = getLogger('aiofastnet')

cdef object _DATA_RECEIVED_MAX_SIZE = 256 * 1024


cdef inline Py_ssize_t aiofn_recv(int sockfd, void* buf, Py_ssize_t len) except? -1:
    cdef:
        ssize_t bytes_read
        int last_error

    while True:
        bytes_read = recv(sockfd, buf, len, 0)
        if bytes_read >= 0:
            return bytes_read

        last_error = aiofn_get_last_error()
        if last_error in (AIOFN_EWOULDBLOCK, AIOFN_EAGAIN):
            return bytes_read

        if not AIOFN_IS_WINDOWS and last_error == errno.EINTR:
            continue

        aiofn_set_exc_from_error(last_error)

        return bytes_read


cdef inline Py_ssize_t aiofn_send(int sockfd, void* buf, Py_ssize_t len) except? -1:
    cdef:
        ssize_t bytes_sent
        int last_error

    while True:
        bytes_sent = send(sockfd, buf, len, 0)
        if bytes_sent > 0:
            return bytes_sent

        if bytes_sent == -1:
            last_error = aiofn_get_last_error()
            if last_error in (AIOFN_EWOULDBLOCK, AIOFN_EAGAIN):
                return bytes_sent

            if not AIOFN_IS_WINDOWS and last_error == errno.EINTR:
                continue

            aiofn_set_exc_from_error(last_error)
            return bytes_sent

        if bytes_sent == 0:
            # This should never happen, but who knows?
            # May be len is 0?
            raise RuntimeError(f"send syscall has sent 0 bytes and did not indicate any error, buf_len={len}")


cdef inline Py_ssize_t aiofn_writev(int sockfd, aiofn_iovec* iov, Py_ssize_t iovcnt) except? -1:
    cdef:
        ssize_t bytes_sent
        int last_error

    while True:
        bytes_sent = aiofn_writev_sys(sockfd, iov, iovcnt)

        if bytes_sent > 0:
            return bytes_sent

        if bytes_sent == -1:
            last_error = aiofn_get_last_error()
            if last_error in (AIOFN_EWOULDBLOCK, AIOFN_EAGAIN):
                return bytes_sent

            if not AIOFN_IS_WINDOWS and last_error == errno.EINTR:
                continue

            aiofn_set_exc_from_error(last_error)
            return bytes_sent

        if bytes_sent == 0:
            # This should never happen, but who knows?
            # May be len is 0?
            raise RuntimeError(f"writev syscall has sent 0 bytes and did not indicate any error")


cdef _set_result_unless_cancelled(fut, result):
    """Helper setting the result only if the future was not cancelled."""
    if fut.cancelled():
        return
    fut.set_result(result)


cdef _set_nodelay(sock):
    if hasattr(socket, 'TCP_NODELAY'):
        if (sock.family in {socket.AF_INET, socket.AF_INET6} and
                sock.type == socket.SOCK_STREAM and
                sock.proto == socket.IPPROTO_TCP):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


cdef class Transport:
    cpdef write(self, data):
        raise NotImplemented

    cpdef writelines(self, list_of_data):
        raise NotImplemented

    cdef write_mem(self, char* ptr, Py_ssize_t sz):
        raise NotImplemented


cdef class Protocol:
    cpdef is_buffered_protocol(self):
        return None

    cpdef get_local_write_buffer_size(self):
        return 0

    cpdef get_buffer(self, Py_ssize_t hint):
        raise NotImplemented

    cpdef buffer_updated(self, Py_ssize_t bytes_read):
        raise NotImplemented

    cpdef data_received(self, data):
        raise NotImplemented


cpdef is_buffered_protocol(protocol):
    try:
        ret = getattr(protocol, 'is_buffered_protocol')()
        if ret is not None:
            return ret
    except AttributeError:
        pass

    return isinstance(protocol, BufferedProtocol)


cdef class SelectorSocketTransport(Transport):
    cdef:
        object __weakref__
        object _loop
        object _protocol
        bint _protocol_buffered
        bint _protocol_aiofn
        bint _protocol_connected
        bint _protocol_paused
        Py_ssize_t _high_water
        Py_ssize_t _low_water
        dict _extra

        object _sock
        int _sock_fd
        object _server
        object _write_backlog
        int _conn_lost
        bint _closing
        bint _paused

        bint _eof
        object _empty_waiter
        bint _send_again_after_partial_send

        aiofn_iovec _iovecs[256]

    def __init__(self, loop, sock, protocol, waiter=None, extra=None, server=None):
        assert loop is not None
        self._loop = loop
        self.set_protocol(protocol)
        self._set_write_buffer_limits()
        self._extra = {} if extra is None else extra
        self._extra['socket'] = TransportSocket(sock)
        try:
            self._extra['sockname'] = sock.getsockname()
        except OSError:
            self._extra['sockname'] = None
        if 'peername' not in self._extra:
            try:
                self._extra['peername'] = sock.getpeername()
            except socket.error:
                self._extra['peername'] = None
        self._sock = sock
        self._sock_fd = sock.fileno()
        self._server = server
        self._write_backlog = collections.deque()
        self._conn_lost = 0  # Set when call to connection_lost scheduled.
        self._closing = False  # Set when close() called.
        self._paused = False  # Set when pause_reading() called

        if self._server is not None:
            self._server._attach(self)

        self._eof = False
        self._empty_waiter = None

        # Enable this to experiment with calling send again until we get EAGAIN
        # after successful partial send
        self._send_again_after_partial_send = False

        _set_nodelay(self._sock)

        self._loop.call_soon(self._protocol.connection_made, self)
        # only start reading when connection_made() has been called
        self._loop.call_soon(self._loop.add_reader,
                             self._sock_fd, self._read_ready)
        if waiter is not None:
            # only wake up the waiter when connection_made() has been called
            self._loop.call_soon(_set_result_unless_cancelled, waiter, None)

    def __repr__(self):
        info = [self.__class__.__name__]
        if self._sock is None:
            info.append('closed')
        elif self._closing:
            info.append('closing')
        info.append(f'fd={self._sock_fd}')
        # test if the transport was closed
        if self._loop is not None and not self._loop.is_closed():
            bufsize = self.get_write_buffer_size()
            info.append(f', bufsize={bufsize}>')
        return '<{}>'.format(' '.join(info))

    def __del__(self):
        if self._sock is not None:
            warnings.warn(f"unclosed transport {self!r}", ResourceWarning, source=self)
            self._sock.close()
            if self._server is not None:
                self._server._detach(self)

    cpdef set_protocol(self, protocol):
        self._protocol = protocol
        self._protocol_buffered = is_buffered_protocol(protocol)
        self._protocol_aiofn = isinstance(protocol, Protocol)
        self._protocol_connected = True

    cpdef get_protocol(self):
        return self._protocol

    cpdef get_extra_info(self, name, default=None):
        """Get optional transport information."""
        return self._extra.get(name, default)

    cpdef tuple get_write_buffer_limits(self):
        return (self._low_water, self._high_water)

    cpdef set_write_buffer_limits(self, high=None, low=None):
        self._set_write_buffer_limits(high=high, low=low)
        self._maybe_pause_protocol()

    cpdef abort(self):
        self._force_close(None)

    cpdef is_closing(self):
        return self._closing

    cpdef is_reading(self):
        return not self.is_closing() and not self._paused

    cpdef pause_reading(self):
        if not self.is_reading():
            return
        self._paused = True
        self._loop.remove_reader(self._sock_fd)
        if self._loop.get_debug():
            _logger.debug("%r pauses reading", self)

    cpdef resume_reading(self):
        if self._closing or not self._paused:
            return
        self._paused = False

        if not self.is_reading():
            return
        self._loop.add_reader(self._sock_fd, self._read_ready)

        if self._loop.get_debug():
            _logger.debug("%r resumes reading", self)

    cpdef close(self):
        if self._closing:
            return
        self._closing = True
        self._loop.remove_reader(self._sock_fd)
        if not self._write_backlog:
            self._conn_lost += 1
            self._loop.remove_writer(self._sock_fd)
            self._loop.call_soon(self._call_connection_lost, None)

    cpdef get_write_buffer_size(self):
        cdef Py_ssize_t total = 0
        for data in self._write_backlog:
            total += len(data)

        if isinstance(self._protocol, Protocol):
            total += (<Protocol>self._protocol).get_local_write_buffer_size()

        return total

    def _read_ready(self):
        if self._protocol_buffered:
            self._read_ready__get_buffer()
        else:
            self._read_ready__data_received()

    cdef inline _read_ready__get_buffer(self):
        cdef:
            object buf
            char* buf_ptr
            Py_ssize_t buf_len
            Py_ssize_t bytes_read

        while True:
            if self._conn_lost:
                return

            try:
                if self._protocol_aiofn:
                    buf = (<Protocol>self._protocol).get_buffer(-1)
                else:
                    buf = self._protocol.get_buffer(-1)

                aiofn_unpack_buffer(buf, &buf_ptr, &buf_len)
                if buf_len == 0:
                    raise RuntimeError('get_buffer() returned an empty buffer')
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._fatal_error(
                    exc, 'Fatal error: protocol.get_buffer() call failed.')
                return

            try:
                bytes_read = aiofn_recv(self._sock_fd, buf_ptr, buf_len)
                if bytes_read == -1:    # without exception this means EGAIN
                    return
            except (BlockingIOError, InterruptedError):
                return
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._fatal_error(exc, 'Fatal read error on socket transport')
                return

            if bytes_read == 0:
                self._read_ready__on_eof()
                return

            try:
                if self._protocol_aiofn:
                    buf = (<Protocol>self._protocol).buffer_updated(bytes_read)
                else:
                    buf = self._protocol.buffer_updated(bytes_read)
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._fatal_error(
                    exc, 'Fatal error: protocol.buffer_updated() call failed.')

    cdef inline _read_ready__data_received(self):
        if self._conn_lost:
            return
        try:
            # Already a good wrapper, returns bytes object.
            # Exactly what we need for non-buffered protocols
            data = self._sock.recv(_DATA_RECEIVED_MAX_SIZE)
        except (BlockingIOError, InterruptedError):
            return
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._fatal_error(exc, 'Fatal read error on socket transport')
            return

        if not data:
            self._read_ready__on_eof()
            return

        try:
            if self._protocol_aiofn:
                (<Protocol>self._protocol).data_received(data)
            else:
                self._protocol.data_received(data)
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._fatal_error(
                exc, 'Fatal error: protocol.data_received() call failed.')

    cdef inline _read_ready__on_eof(self):
        if self._loop.get_debug():
            _logger.debug("%r received EOF", self)

        try:
            keep_open = self._protocol.eof_received()
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._fatal_error(
                exc, 'Fatal error: protocol.eof_received() call failed.')
            return

        if keep_open:
            # We're keeping the connection open so the
            # protocol can write more, but we still can't
            # receive more, so remove the reader callback.
            self._loop.remove_reader(self._sock_fd)
        else:
            self.close()

    cpdef write(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f'data argument must be a bytes, bytearray, or memoryview '
                            f'object, not {type(data).__name__!r}')
        if self._eof:
            raise RuntimeError('Cannot call write() after write_eof()')
        if self._empty_waiter is not None:
            raise RuntimeError('unable to write; sendfile is in progress')
        if not data:
            return

        if self._conn_lost:
            if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                _logger.warning('socket.send() raised exception.')
            self._conn_lost += 1
            return

        cdef:
            char* data_ptr
            Py_ssize_t data_len, data_len_init = 0
            Py_ssize_t bytes_sent

        if not self._write_backlog:
            aiofn_unpack_buffer(data, &data_ptr, &data_len)
            data = self._write_one(data, data_ptr, data_len)
            if data is None:
                return

            # Not all was written; register write handler.
            self._loop.add_writer(self._sock_fd, self._write_ready)
        else:
            data = aiofn_maybe_copy_buffer(data)

        self._write_backlog.append(data)
        self._maybe_pause_protocol()

    cdef write_mem(self, char* ptr, Py_ssize_t sz):
        if sz <= 0:
            return

        if self._conn_lost:
            if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                _logger.warning('socket.send() raised exception.')
            self._conn_lost += 1
            return

        if not self._write_backlog:
            data = self._write_one(None, ptr, sz)
            if data is None:
                return

            # Not all was written; register write handler.
            self._loop.add_writer(self._sock_fd, self._write_ready)
        else:
            data = PyBytes_FromStringAndSize(ptr, sz)

        self._write_backlog.append(data)
        self._maybe_pause_protocol()

    cpdef writelines(self, list_of_data):
        if self._eof:
            raise RuntimeError('Cannot call writelines() after write_eof()')
        if self._empty_waiter is not None:
            raise RuntimeError('unable to writelines; sendfile is in progress')
        if not list_of_data:
            return

        if self._conn_lost:
            if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                _logger.warning('socket.send() raised exception.')
            self._conn_lost += 1
            return

        if self._write_backlog:
            for data in list_of_data:
                self._write_backlog.append(aiofn_maybe_copy_buffer(data))
            self._maybe_pause_protocol()
            return

        self._write_many(list_of_data)

        # If the entire buffer couldn't be written, register a write handler
        if self._write_backlog:
            self._loop.add_writer(self._sock_fd, self._write_ready)
            self._maybe_pause_protocol()

    cpdef can_write_eof(self):
        return True

    cpdef write_eof(self):
        if self._closing or self._eof:
            return
        self._eof = True
        if not self._write_backlog:
            self._sock.shutdown(socket.SHUT_WR)

    cdef inline _write_one(self, object data, char* data_ptr, Py_ssize_t data_len):
        """
        Returns None if all data has been sent, or remaining data
        """
        cdef Py_ssize_t bytes_sent

        while True:
            try:
                bytes_sent = aiofn_send(self._sock_fd, data_ptr, data_len)
            except (BlockingIOError, InterruptedError):
                pass
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._fatal_error(exc, 'Fatal write error on socket transport')
                return
            else:
                if bytes_sent == data_len:
                    return None

                if bytes_sent == -1:
                    return aiofn_maybe_copy_buffer_tail(data, data_ptr, data_len)

                data_ptr += bytes_sent
                data_len -= bytes_sent

                # if _send_again_after_partial_send is True, retry send
                # until EAGAIN
                if not self._send_again_after_partial_send:
                    return aiofn_maybe_copy_buffer_tail(data, data_ptr, data_len)

    cdef inline _adjust_leftover_buffer(self, list_of_data, Py_ssize_t bytes_sent):
        cdef:
            char* data_ptr
            Py_ssize_t data_len

        if list_of_data is not self._write_backlog:
            for data in list_of_data:
                aiofn_unpack_buffer(data, &data_ptr, &data_len)
                if data_len <= bytes_sent:
                    bytes_sent -= data_len
                    continue
                elif bytes_sent <= 0:
                    self._write_backlog.append(aiofn_maybe_copy_buffer(data))
                else:
                    data_ptr += bytes_sent
                    data_len -= bytes_sent
                    self._write_backlog.append(aiofn_maybe_copy_buffer_tail(data, data_ptr, data_len))
        else:
            while bytes_sent > 0:
                data = self._write_backlog.popleft()
                data_len = len(data)
                if data_len <= bytes_sent:
                    bytes_sent -= data_len
                else:
                    self._write_backlog.appendleft(data[bytes_sent:])
                    break

    cdef inline _write_many(self, list_of_data):
        cdef:
            Py_ssize_t idx = 0
            char* data_ptr
            Py_ssize_t data_len

        for idx, data in enumerate(list_of_data):
            aiofn_unpack_buffer(data, &data_ptr, &data_len)
            self._iovecs[idx].iov_base = data_ptr
            self._iovecs[idx].iov_len = data_len
            if idx == AIOFN_MAX_IOVEC - 1:
                break

        cdef Py_ssize_t bytes_sent = aiofn_writev(self._sock_fd, self._iovecs, idx + 1)
        self._adjust_leftover_buffer(list_of_data, bytes_sent)

    cpdef _write_ready(self):
        assert self._write_backlog, 'Data should not be empty'
        if self._conn_lost:
            return
        try:
            self._write_many(self._write_backlog)
        except (BlockingIOError, InterruptedError):
            pass
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._loop.remove_writer(self._sock_fd)
            self._write_backlog.clear()
            self._fatal_error(exc, 'Fatal write error on socket transport')
            if self._empty_waiter is not None:
                self._empty_waiter.set_exception(exc)
        else:
            self._maybe_resume_protocol()
            if not self._write_backlog:
                self._loop.remove_writer(self._sock_fd)
                if self._empty_waiter is not None:
                    self._empty_waiter.set_result(None)
                if self._closing:
                    self._conn_lost += 1
                    self._call_connection_lost(None)
                elif self._eof:
                    self._sock.shutdown(socket.SHUT_WR)

    cpdef _call_connection_lost(self, exc):
        try:
            try:
                if self._protocol_connected:
                    self._protocol.connection_lost(exc)
            finally:
                self._sock.close()
                self._sock = None
                self._protocol = None
                self._loop = None
                server = self._server
                if server is not None:
                    server._detach(self)
                    self._server = None
        finally:
            if self._empty_waiter is not None:
                self._empty_waiter.set_exception(
                    ConnectionError("Connection is closed by peer"))

    cdef inline _make_empty_waiter(self):
        if self._empty_waiter is not None:
            raise RuntimeError("Empty waiter is already set")
        self._empty_waiter = self._loop.create_future()
        if not self._write_backlog:
            self._empty_waiter.set_result(None)
        return self._empty_waiter

    cdef inline _reset_empty_waiter(self):
        self._empty_waiter = None

    cdef inline _maybe_pause_protocol(self):
        cdef Py_ssize_t size = self.get_write_buffer_size()
        if size <= self._high_water:
            return
        if not self._protocol_paused:
            self._protocol_paused = True
            try:
                self._protocol.pause_writing()
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._loop.call_exception_handler({
                    'message': 'protocol.pause_writing() failed',
                    'exception': exc,
                    'transport': self,
                    'protocol': self._protocol,
                })

    cdef inline _maybe_resume_protocol(self):
        if (self._protocol_paused and
                self.get_write_buffer_size() <= self._low_water):
            self._protocol_paused = False
            try:
                self._protocol.resume_writing()
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._loop.call_exception_handler({
                    'message': 'protocol.resume_writing() failed',
                    'exception': exc,
                    'transport': self,
                    'protocol': self._protocol,
                })

    cdef inline _set_write_buffer_limits(self, high=None, low=None):
        if high is None:
            if low is None:
                high = 64 * 1024
            else:
                high = 4 * low
        if low is None:
            low = high // 4

        if not high >= low >= 0:
            raise ValueError(
                f'high ({high!r}) must be >= low ({low!r}) must be >= 0')

        self._high_water = high
        self._low_water = low

    cdef inline _fatal_error(self, exc, message='Fatal error on transport'):
        # Should be called from exception handler only.
        if isinstance(exc, OSError):
            if self._loop.get_debug():
                _logger.debug("%r: %s", self, message, exc_info=True)
        else:
            self._loop.call_exception_handler({
                'message': message,
                'exception': exc,
                'transport': self,
                'protocol': self._protocol,
            })
        self._force_close(exc)

    # May be used by create_connection/create_server
    # Keep cpdef
    cpdef _force_close(self, exc):
        if self._conn_lost:
            return
        if self._write_backlog:
            self._write_backlog.clear()
            self._loop.remove_writer(self._sock_fd)
        if not self._closing:
            self._closing = True
            self._loop.remove_reader(self._sock_fd)
        self._conn_lost += 1
        self._loop.call_soon(self._call_connection_lost, exc)

