import collections
import os
import socket
import warnings
from itertools import islice
from asyncio.trsock import TransportSocket
from asyncio import BufferedProtocol
from logging import getLogger

from .system cimport *

from . import constants

from cpython.buffer cimport (
    PyObject_GetBuffer,
    PyBuffer_Release,
    PyBUF_SIMPLE
)


cdef _logger = getLogger('fastnet')

cdef bint _HAS_SENDMSG = _get_has_sendmsg()
cdef Py_ssize_t _SC_IOV_MAX = os.sysconf('SC_IOV_MAX') if _HAS_SENDMSG else 0


cdef _get_has_sendmsg():
    if hasattr(socket.socket, 'sendmsg'):
        try:
            os.sysconf('SC_IOV_MAX')
            return True
        except OSError:
            return False


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

    cdef write_mem(self, char* ptr, Py_ssize_t sz):
        raise NotImplemented


cdef class Protocol:
    cpdef is_buffered_protocol(self):
        return None

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


cdef call_get_buffer(protocol, Py_ssize_t hint):
    if isinstance(protocol, Protocol):
        return (<Protocol>protocol).get_buffer(hint)
    else:
        return protocol.get_buffer(hint)


cdef call_buffer_updated(protocol, Py_ssize_t bytes_read):
    if isinstance(protocol, Protocol):
        return (<Protocol>protocol).buffer_updated(bytes_read)
    else:
        return protocol.buffer_updated(bytes_read)


cdef call_data_received(protocol, data):
    if isinstance(protocol, Protocol):
        return (<Protocol>protocol).data_received(data)
    else:
        return protocol.data_received(data)


cdef class SelectorSocketTransport(Transport):
    cdef:
        object __weakref__
        object _loop
        object _protocol
        bint _protocol_buffered
        bint _protocol_connected
        bint _protocol_paused
        Py_ssize_t _high_water
        Py_ssize_t _low_water
        dict _extra

        object _sock
        int _sock_fd
        object _server
        object _buffer
        int _conn_lost
        bint _closing
        bint _paused

        bint _eof
        object _empty_waiter
        bint _send_again_after_partial_send

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
        self._buffer = collections.deque()
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
        if not self._buffer:
            self._conn_lost += 1
            self._loop.remove_writer(self._sock_fd)
            self._loop.call_soon(self._call_connection_lost, None)

    cpdef get_write_buffer_size(self):
        return sum(map(len, self._buffer))

    def _read_ready(self):
        if self._protocol_buffered:
            self._read_ready__get_buffer()
        else:
            self._read_ready__data_received()

    cdef inline _read_ready__get_buffer(self):
        cdef:
            object buf
            Py_buffer pybuf
            char* buf_ptr
            Py_ssize_t buf_len
            Py_ssize_t bytes_read

        while True:
            if self._conn_lost:
                return

            try:
                buf = call_get_buffer(self._protocol, -1)
                if not len(buf):
                    raise RuntimeError('get_buffer() returned an empty buffer')
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._fatal_error(
                    exc, 'Fatal error: protocol.get_buffer() call failed.')
                return

            try:
                PyObject_GetBuffer(buf, &pybuf, PyBUF_SIMPLE)
                buf_ptr = <char*> pybuf.buf
                buf_len = pybuf.len
                PyBuffer_Release(&pybuf)

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
                call_buffer_updated(self._protocol, bytes_read)
            except (SystemExit, KeyboardInterrupt):
                raise
            except BaseException as exc:
                self._fatal_error(
                    exc, 'Fatal error: protocol.buffer_updated() call failed.')

    cdef inline _read_ready__data_received(self):
        if self._conn_lost:
            return
        try:
            data = self._sock.recv(self.max_size)
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
            call_data_received(self._protocol, data)
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

        if not self._buffer:
            aiofn_unpack_buffer(data, &data_ptr, &data_len)
            data = self._write_now(data, data_ptr, data_len)
            if data is None:
                return

            # Not all was written; register write handler.
            self._loop.add_writer(self._sock_fd, self._write_ready)
        else:
            data = aiofn_maybe_copy_buffer(data)

        self._buffer.append(data)
        self._maybe_pause_protocol()

    cdef write_mem(self, char* ptr, Py_ssize_t sz):
        if sz <= 0:
            return

        if self._conn_lost:
            if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                _logger.warning('socket.send() raised exception.')
            self._conn_lost += 1
            return

        if not self._buffer:
            data = self._write_now(None, ptr, sz)
            if data is None:
                return

            # Not all was written; register write handler.
            self._loop.add_writer(self._sock_fd, self._write_ready)
        else:
            data = PyBytes_FromStringAndSize(ptr, sz)

        self._buffer.append(data)
        self._maybe_pause_protocol()

    cdef inline _write_now(self, object data, char* data_ptr, Py_ssize_t data_len):
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

    cdef inline _get_sendmsg_buffer(self):
        return islice(self._buffer, _SC_IOV_MAX)

    def _write_ready(self):
        if _HAS_SENDMSG:
            return self._write_sendmsg()
        else:
            return self._write_send()

    cdef inline _write_sendmsg(self):
        assert self._buffer, 'Data should not be empty'
        if self._conn_lost:
            return
        try:
            nbytes = self._sock.sendmsg(self._get_sendmsg_buffer())

            self._adjust_leftover_buffer(nbytes)
        except (BlockingIOError, InterruptedError):
            pass
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._loop.remove_writer(self._sock_fd)
            self._buffer.clear()
            self._fatal_error(exc, 'Fatal write error on socket transport')
            if self._empty_waiter is not None:
                self._empty_waiter.set_exception(exc)
        else:
            self._maybe_resume_protocol()  # May append to buffer.
            if not self._buffer:
                self._loop.remove_writer(self._sock_fd)
                if self._empty_waiter is not None:
                    self._empty_waiter.set_result(None)
                if self._closing:
                    self._call_connection_lost(None)
                elif self._eof:
                    self._sock.shutdown(socket.SHUT_WR)

    cdef inline _adjust_leftover_buffer(self, Py_ssize_t nbytes):
        buffer = self._buffer
        while nbytes:
            b = buffer.popleft()
            b_len = len(b)
            if b_len <= nbytes:
                nbytes -= b_len
            else:
                buffer.appendleft(b[nbytes:])
                break

    cdef inline _write_send(self):
        assert self._buffer, 'Data should not be empty'
        if self._conn_lost:
            return
        try:
            buffer = self._buffer.popleft()
            n = self._sock.send(buffer)
            if n != len(buffer):
                # Not all data was written
                self._buffer.appendleft(buffer[n:])
        except (BlockingIOError, InterruptedError):
            pass
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            self._loop.remove_writer(self._sock_fd)
            self._buffer.clear()
            self._fatal_error(exc, 'Fatal write error on socket transport')
            if self._empty_waiter is not None:
                self._empty_waiter.set_exception(exc)
        else:
            self._maybe_resume_protocol()  # May append to buffer.
            if not self._buffer:
                self._loop.remove_writer(self._sock_fd)
                if self._empty_waiter is not None:
                    self._empty_waiter.set_result(None)
                if self._closing:
                    self._call_connection_lost(None)
                elif self._eof:
                    self._sock.shutdown(socket.SHUT_WR)

    cpdef write_eof(self):
        if self._closing or self._eof:
            return
        self._eof = True
        if not self._buffer:
            self._sock.shutdown(socket.SHUT_WR)

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

        self._buffer.extend([memoryview(data) for data in list_of_data])
        self._write_ready()
        # If the entire buffer couldn't be written, register a write handler
        if self._buffer:
            self._loop.add_writer(self._sock_fd, self._write_ready)
            self._maybe_pause_protocol()

    cpdef can_write_eof(self):
        return True

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
        if not self._buffer:
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
        if self._buffer:
            self._buffer.clear()
            self._loop.remove_writer(self._sock_fd)
        if not self._closing:
            self._closing = True
            self._loop.remove_reader(self._sock_fd)
        self._conn_lost += 1
        self._loop.call_soon(self._call_connection_lost, exc)

