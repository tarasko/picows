import asyncio
import ssl
import warnings
from logging import getLogger

from cpython.contextvars cimport *
from cpython.buffer cimport *
from cpython.bytearray cimport *
from cpython.unicode cimport *

from . import constants
from .system cimport *
from .openssl cimport *
from .transport cimport *


cdef enum:
    SSL_READ_DEFAULT_SIZE = 64 * 1024
    SSL_READ_MAX_SIZE = 256 * 1024


cdef extern from *:
    """
    // Number of seconds to wait for SSL handshake to complete
    // The default timeout matches that of Nginx.
    #define SSL_HANDSHAKE_TIMEOUT 60.0

    // Number of seconds to wait for SSL shutdown to complete
    // The default timeout mimics lingering_time
    #define SSL_SHUTDOWN_TIMEOUT 30.0
    """

    const float SSL_HANDSHAKE_TIMEOUT
    const float SSL_SHUTDOWN_TIMEOUT


# A memory layout hack to extract SSL_CTX* ptr from python SSLContext object.
#
# I intentionally mirror ONLY the initial prefix of CPython's PySSLContext:
# PyObject_HEAD + SSL_CTX *ctx
#
# This is NOT ABI-stable and may break across Python versions/build options.
# I know it is ugly, but who cares, in some million years the sun will destroy
# all life on earth, so everything is meaningless anyway.
#
# The guys from python are reluctant to expose it directly:
# https://bugs.python.org/issue43902

cdef object _logger = getLogger('picows.ssl')


ctypedef struct PySSLContextHack:
    PyObject ob_base
    SSL_CTX *ctx


cdef SSL_CTX* _get_ssl_ctx_ptr(object py_ctx) except NULL:
    # Minimal runtime sanity check (still not foolproof)
    if not isinstance(py_ctx, ssl.SSLContext):
        raise TypeError("expected ssl.SSLContext")

    # Layout-cast hack:
    return (<PySSLContextHack*> <PyObject*> py_ctx).ctx


cdef dict _lib_to_name = {
    ERR_LIB_SSL: "SSL",
    ERR_LIB_X509: "X509",
    ERR_LIB_X509V3: "X509V3",
    ERR_LIB_PEM: "PEM",
    ERR_LIB_ASN1: "ASN1",
    ERR_LIB_EVP: "EVP",
    ERR_LIB_BIO: "BIO",
    ERR_LIB_SYS: "SYS",
    ERR_LIB_PKCS12: "PKCS12",
    ERR_LIB_PKCS7: "PKCS7",
    ERR_LIB_RAND: "RAND",
    ERR_LIB_CONF: "CONF",
    ERR_LIB_ENGINE: "ENGINE",
    ERR_LIB_OCSP: "OCSP",
    ERR_LIB_UI: "UI",
    ERR_LIB_TS: "TS",
    ERR_LIB_CMS: "CMS",
    ERR_LIB_CRYPTO: "CRYPTO",
}


cdef int _print_error_cb(const char* str, size_t len, void* u) noexcept nogil:
    with gil:
        logger = <object><PyObject*>u
        err_str = PyUnicode_FromStringAndSize(str, len)
        logger.error(err_str)


cdef _log_error_queue():
    cdef void* u = <PyObject*>_logger
    ERR_print_errors_cb(&_print_error_cb, u)


cdef unsigned long _err_last_error():
    cdef unsigned long err_code = ERR_peek_last_error()
    ERR_clear_error()
    return err_code


cdef Py_ssize_t _bio_pending(BIO* bio):
    cdef int pending = BIO_pending(bio)
    if pending < 0:
        raise RuntimeError("unable to get pending len from BIO")
    return pending


cdef class SSLConnection:
    def __init__(self, ssl_context, bint is_server, str server_hostname):
        ERR_clear_error()

        self.ssl_ctx_py = ssl_context
        self.ssl_ctx = _get_ssl_ctx_ptr(ssl_context)
        self.incoming = BIO_new(BIO_s_mem())
        self.outgoing = BIO_new(BIO_s_mem())
        self.ssl_object = SSL_new(self.ssl_ctx)
        self.server_hostname = server_hostname
        if is_server:
            SSL_set_accept_state(self.ssl_object)
        else:
            SSL_set_connect_state(self.ssl_object)
        SSL_set_bio(self.ssl_object, self.incoming, self.outgoing)
        BIO_set_nbio(self.incoming, 1)
        BIO_set_nbio(self.outgoing, 1)

        cdef:
            X509_VERIFY_PARAM* ssl_verification_params
            X509_VERIFY_PARAM* ssl_ctx_verification_params
            unsigned int ssl_ctx_host_flags

        if OPENSSL_VERSION_NUMBER < 0x101010cf:
            ssl_verification_params = SSL_get0_param(self.ssl_object)
            ssl_ctx_verification_params = SSL_CTX_get0_param(self.ssl_ctx)

            ssl_ctx_host_flags = X509_VERIFY_PARAM_get_hostflags(ssl_ctx_verification_params)
            X509_VERIFY_PARAM_set_hostflags(ssl_verification_params, ssl_ctx_host_flags)

        SSL_set_mode(self.ssl_object, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY)

        if self.server_hostname is not None:
            self._configure_hostname()

    def __dealloc__(self):
        # Free SSL and its BIO
        SSL_free(self.ssl_object)

    cdef tuple cipher(self):
        cdef const SSL_CIPHER* c = SSL_get_current_cipher(self.ssl_object)

        cdef const char* name = SSL_CIPHER_get_name(c)
        name_obj = PyUnicode_FromString(name) if name != NULL else None

        cdef const char* protocol = SSL_CIPHER_get_version(c)
        protocol_obj = PyUnicode_FromString(protocol) if name != NULL else None

        cdef int bits = SSL_CIPHER_get_bits(c, NULL)

        return (name_obj, protocol_obj, bits)

    cdef dict getpeercert(self):
        if SSL_is_init_finished(self.ssl_object) != 1:
            raise ssl.SSLError("SSL_is_init_finished failed")

        cdef X509* peer_cert = SSL_get_peer_certificate(self.ssl_object)
        if peer_cert == NULL:
            return None

        cdef int verification = SSL_CTX_get_verify_mode(self.ssl_ctx)
        try:
            return self._decode_certificate(peer_cert) if verification & SSL_VERIFY_PEER else dict()
        finally:
            X509_free(peer_cert)

    # TODO: I don't think people would need this.
    # For now I return None but if somebody asks can be made compatible with
    # python implementation
    cdef str compression(self):
        return None

    cdef make_exc_from_ssl_error(self, str descr, int err_code):
        assert err_code != SSL_ERROR_NONE, "check logic"
        cdef char err_string[256]
        cdef unsigned long last_error
        cdef int lib, reason

        if err_code == SSL_ERROR_WANT_READ:
            return ssl.SSLWantReadError(descr)
        elif err_code == SSL_ERROR_WANT_WRITE:
            return ssl.SSLWantWriteError(descr)
        elif err_code == SSL_ERROR_ZERO_RETURN:
            return ssl.SSLZeroReturnError(descr)
        elif err_code == SSL_ERROR_SYSCALL:
            return ssl.SSLSyscallError(descr)
        elif err_code == SSL_ERROR_SSL:
            return self._exc_from_err_last_error(descr)
        else:
            return ssl.SSLError(f"{descr}, unknown error_code={err_code}")

    cdef _exc_from_err_last_error(self, str descr):
        cdef unsigned long last_error = _err_last_error()
        cdef int lib = ERR_GET_LIB(last_error)
        cdef int reason = ERR_GET_REASON(last_error)

        if _logger is not None:
            _log_error_queue(_logger)

        lib_name = _lib_to_name.get(lib, "UNKNOWN")
        cdef const char * reason_ptr = ERR_reason_error_string(last_error)
        reason_name = PyUnicode_FromString(
            reason_ptr) if reason_ptr != NULL else ""
        reason_name = reason_name.upper().replace(" ", "_")

        if reason == SSL_R_CERTIFICATE_VERIFY_FAILED:
            assert self.server_hostname is not None
            verify_code = SSL_get_verify_result(self.ssl_object)
            if verify_code == X509_V_ERR_HOSTNAME_MISMATCH:
                txt = f"Hostname mismatch, certificate is not valid for '{self.server_hostname}'"
            elif verify_code == X509_V_ERR_IP_ADDRESS_MISMATCH:
                txt = f"IP address mismatch, certificate is not valid for '{self.server_hostname}'"
            else:
                verify_str = X509_verify_cert_error_string(verify_code)
                txt = PyUnicode_FromString(
                    verify_str) if verify_str != NULL else ""
            str_error = f"[{lib_name}: {reason_name}] {descr}: {txt}"
            exc = ssl.SSLCertVerificationError()
            exc.verify_code = verify_code
            exc.verify_message = txt
        else:
            str_error = f"[{lib_name}: {reason_name}] {descr}"
            exc = ssl.SSLError()
        exc.strerror = str_error
        exc.library = lib_name
        exc.reason = reason_name
        return exc

    cdef _configure_hostname(self):
        if not self.server_hostname or self.server_hostname.startswith("."):
            raise ValueError("server_hostname cannot be an empty string or start with a leading dot.")

        cdef bytes server_hostname_b = self.server_hostname.encode()
        cdef char* server_hostname_ptr = PyBytes_AS_STRING(server_hostname_b)

        cdef ASN1_OCTET_STRING* ip = a2i_IPADDRESS(PyBytes_AS_STRING(server_hostname_b))
        if ip == NULL:
            ERR_clear_error()

        cdef X509_VERIFY_PARAM* ssl_verification_params
        try:
            # Only send SNI extension for non-IP hostnames
            if ip == NULL:
                if not SSL_set_tlsext_host_name(self.ssl_object, server_hostname_ptr):
                    _log_error_queue(_logger)
                    ERR_clear_error()
                    raise ssl.SSLError("SSL_set_tlsext_host_name failed")

            if self.ssl_ctx_py.check_hostname:
                ssl_verification_params = SSL_get0_param(self.ssl_object)
                if ip == NULL:
                    if not X509_VERIFY_PARAM_set1_host(ssl_verification_params, server_hostname_ptr, len(server_hostname_b)):
                        raise ssl.SSLError("X509_VERIFY_PARAM_set1_host failed")
                else:
                    if not X509_VERIFY_PARAM_set1_ip(ssl_verification_params, ASN1_STRING_get0_data(ip), ASN1_STRING_length(ip)):
                        raise ssl.SSLError("X509_VERIFY_PARAM_set1_host failed")
        finally:
            if ip != NULL:
                ASN1_OCTET_STRING_free(ip)

    # TODO: Implement this
    cdef _decode_certificate(self, X509* certificate):
        cdef dict retval = dict()
        return retval


cdef inline _run_in_context(context, method):
    PyContext_Enter(context)
    try:
        return method()
    finally:
        PyContext_Exit(context)


cdef inline _create_transport_context(server_side, server_hostname):
    # Client side may pass ssl=True to use a default
    # context; in that case the sslcontext passed is None.
    # The default is secure for client connections.
    # Python 3.4+: use up-to-date strong settings.
    sslcontext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if not server_hostname:
        sslcontext.check_hostname = False
    return sslcontext


cdef class SSLTransport:
    def __cinit__(self, loop, SSLProtocol ssl_protocol, context):
        self._loop = loop
        # SSLProtocol instance
        self._ssl_protocol = ssl_protocol
        self._closed = False
        if context is None:
            context = PyContext_CopyCurrent()
        self.context = context

    def get_extra_info(self, name, default=None):
        """Get optional transport information."""
        return self._ssl_protocol._get_extra_info(name, default)

    def set_protocol(self, protocol):
        self._ssl_protocol.set_app_protocol(protocol)

    def get_protocol(self):
        return self._ssl_protocol._app_protocol

    def is_closing(self):
        return self._closed

    def close(self):
        """Close the transport.

        Buffered data will be flushed asynchronously.  No more data
        will be received.  After all buffered data is flushed, the
        protocol's connection_lost() method will (eventually) called
        with None as its argument.
        """
        self._closed = True
        self._ssl_protocol._start_shutdown(self.context.copy())

    def __dealloc__(self):
        if not self._closed:
            self._closed = True
            warnings.warn(
                "unclosed transport <uvloop.loop.SSLTransport "
                "object>", ResourceWarning)

    def is_reading(self):
        return not self._ssl_protocol._app_reading_paused

    def pause_reading(self):
        """Pause the receiving end.

        No data will be passed to the protocol's data_received()
        method until resume_reading() is called.
        """
        self._ssl_protocol._pause_reading()

    def resume_reading(self):
        """Resume the receiving end.

        Data received will once again be passed to the protocol's
        data_received() method.
        """
        self._ssl_protocol._resume_reading(self.context.copy())

    def set_write_buffer_limits(self, high=None, low=None):
        """Set the high- and low-water limits for write flow control.

        These two values control when to call the protocol's
        pause_writing() and resume_writing() methods.  If specified,
        the low-water limit must be less than or equal to the
        high-water limit.  Neither value can be negative.

        The defaults are implementation-specific.  If only the
        high-water limit is given, the low-water limit defaults to an
        implementation-specific value less than or equal to the
        high-water limit.  Setting high to zero forces low to zero as
        well, and causes pause_writing() to be called whenever the
        buffer becomes non-empty.  Setting low to zero causes
        resume_writing() to be called only once the buffer is empty.
        Use of zero for either limit is generally sub-optimal as it
        reduces opportunities for doing I/O and computation
        concurrently.
        """
        self._ssl_protocol._set_write_buffer_limits(high, low)

    def get_write_buffer_limits(self):
        return self._ssl_protocol._get_write_buffer_limits()

    def get_write_buffer_size(self):
        """Return the current size of the write buffers."""
        return self._ssl_protocol._get_write_buffer_size()

    cpdef write(self, data):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it
        to be sent out asynchronously.
        """
        self._ssl_protocol.write(data)

    cdef write_mem(self, char* ptr, Py_ssize_t sz):
        self._ssl_protocol.write_mem(ptr, sz)

    def writelines(self, list_of_data):
        """Write a list (or any iterable) of data bytes to the transport.

        The default implementation concatenates the arguments and
        calls write() on the result.
        """
        self._ssl_protocol.writelines(list_of_data)

    def write_eof(self):
        """Close the write end after flushing buffered data.

        This raises :exc:`NotImplementedError` right now.
        """
        raise NotImplementedError

    def can_write_eof(self):
        """Return True if this transport supports write_eof(), False if not."""
        return False

    def abort(self):
        """Close the transport immediately.

        Buffered data will be lost.  No more data will be received.
        The protocol's connection_lost() method will (eventually) be
        called with None as its argument.
        """
        self._force_close(None)

    def _force_close(self, exc):
        self._closed = True
        self._ssl_protocol._abort(exc)


cdef class SSLProtocol:
    """SSL protocol.

    Implementation of SSL on top of a socket using incoming and outgoing
    buffers which are ssl.MemoryBIO objects.
    """

    def __init__(self,
                 loop,
                 app_protocol,
                 sslcontext,
                 ssl_handshake_complete_waiter=None,
                 server_side=False, server_hostname=None,
                 call_connection_made=True,
                 ssl_handshake_timeout=None,
                 ssl_shutdown_timeout=None):
        if ssl_handshake_timeout is None:
            ssl_handshake_timeout = SSL_HANDSHAKE_TIMEOUT
        elif ssl_handshake_timeout <= 0:
            raise ValueError(
                f"ssl_handshake_timeout should be a positive number, "
                f"got {ssl_handshake_timeout}")
        if ssl_shutdown_timeout is None:
            ssl_shutdown_timeout = SSL_SHUTDOWN_TIMEOUT
        elif ssl_shutdown_timeout <= 0:
            raise ValueError(
                f"ssl_shutdown_timeout should be a positive number, "
                f"got {ssl_shutdown_timeout}")

        if server_side and not sslcontext:
            raise ValueError('Server side SSL needs a valid SSLContext')

        if not sslcontext or sslcontext == True:
            sslcontext = _create_transport_context(server_side, server_hostname)

        self._server_side = server_side
        self._server_hostname = None if server_side else server_hostname
        self._sslcontext = sslcontext
        self._ssl_connection = None
        # SSL-specific extra info. More info are set when the handshake
        # completes.
        self._extra = dict(sslcontext=sslcontext)

        # App data write buffering
        self._write_backlog = []

        self._loop = loop
        self.set_app_protocol(app_protocol)
        self._app_transport = None
        # transport, ex: SelectorSocketTransport
        self._transport = None
        self._ssl_handshake_timeout = ssl_handshake_timeout
        self._ssl_shutdown_timeout = ssl_shutdown_timeout
        self._ssl_handshake_complete_waiter = ssl_handshake_complete_waiter
        self._tcp_read_buffer = PyByteArray_FromStringAndSize(
            NULL, SSL_READ_DEFAULT_SIZE)

        self._state = UNWRAPPED
        self._conn_lost = 0  # Set when connection_lost called
        if call_connection_made:
            self._app_state = STATE_INIT
        else:
            self._app_state = STATE_CON_MADE

        # Flow Control

        self._app_reading_paused = False

    cpdef is_buffered_protocol(self):
        return True

    cpdef set_app_protocol(self, app_protocol):
        self._app_protocol = app_protocol
        self._app_protocol_is_buffered = is_buffered_protocol(app_protocol)

    cpdef get_app_protocol(self):
        return self._app_protocol

    cpdef get_app_transport(self, context=None):
        if self._app_transport is None:
            self._app_transport = SSLTransport(self._loop, self, context)
        return self._app_transport

    def connection_made(self, transport):
        """Called when the low-level connection is made.

        Start the SSL handshake.
        """
        self._transport = transport
        self._start_handshake()

    def connection_lost(self, exc):
        """Called when the low-level connection is lost or closed.

        The argument is an exception object or None (the latter
        meaning a regular EOF is received or the connection was
        aborted or closed).
        """
        self._write_backlog.clear()

        # TODO: Do we need to read remaining data from BIO?
        # Is it ok to just free ssl_object?
        # self._outgoing_read()

        self._conn_lost += 1

        # Just mark the app transport as closed so that its __dealloc__
        # doesn't complain.
        if self._app_transport is not None:
            self._app_transport._closed = True

        if self._state != DO_HANDSHAKE:
            if self._app_state == STATE_CON_MADE or \
                    self._app_state == STATE_EOF:
                self._app_state = STATE_CON_LOST
                self._loop.call_soon(self._app_protocol.connection_lost, exc)
        self._set_state(UNWRAPPED)
        self._transport = None

        # Decrease ref counters to user instances to avoid cyclic references
        # between user protocol, SSLProtocol and SSLTransport.
        # This helps to deallocate useless objects asap.
        # If not done then some tests like test_create_connection_memory_leak
        # will fail.
        self._app_transport = None
        self._app_protocol = None
        self._wakeup_waiter(exc)

        if self._shutdown_timeout_handle:
            self._shutdown_timeout_handle.cancel()
            self._shutdown_timeout_handle = None
        if self._handshake_timeout_handle:
            self._handshake_timeout_handle.cancel()
            self._handshake_timeout_handle = None

    cpdef get_buffer(self, Py_ssize_t n):
        if n < 0:
            n = 256*1024

        cdef Py_ssize_t want = min(n, SSL_READ_MAX_SIZE)

        if PyByteArray_GET_SIZE(self._tcp_read_buffer) < want:
            PyByteArray_Resize(self._tcp_read_buffer, want)

        cdef char* buf = PyByteArray_AS_STRING(self._tcp_read_buffer)
        cdef size_t buf_size = PyByteArray_GET_SIZE(self._tcp_read_buffer)

        return PyMemoryView_FromMemory(buf, buf_size, PyBUF_WRITE)

    cpdef buffer_updated(self, Py_ssize_t nbytes):
        cdef int bytes_written = BIO_write(
                self._ssl_connection.incoming,
                PyByteArray_AS_STRING(self._tcp_read_buffer),
                nbytes)

        if bytes_written <= 0:
            raise ssl.SSLError(f"incoming BIO: write failed, rc={bytes_written}")
        elif bytes_written != nbytes:
            raise ssl.SSLError(f"incoming BIO: not all bytes have been written: {bytes_written} < {nbytes}")

        if self._state == DO_HANDSHAKE:
            self._do_handshake()

        elif self._state == WRAPPED:
            self._do_read()

        elif self._state == FLUSHING:
            self._do_flush()

        elif self._state == SHUTDOWN:
            self._do_shutdown()

    def eof_received(self):
        """Called when the other end of the low-level stream
        is half-closed.

        If this returns a false value (including None), the transport
        will close itself.  If it returns a true value, closing the
        transport is up to the protocol.
        """
        try:
            if self._loop.get_debug():
                _logger.debug("%r received EOF", self)

            if self._state == DO_HANDSHAKE:
                self._on_handshake_complete(ConnectionResetError)

            elif self._state == WRAPPED or self._state == FLUSHING:
                # We treat a low-level EOF as a critical situation similar to a
                # broken connection - just send whatever is in the buffer and
                # close. No application level eof_received() is called -
                # because we don't want the user to think that this is a
                # graceful shutdown triggered by SSL "close_notify".
                self._set_state(SHUTDOWN)
                self._on_shutdown_complete(None)

            elif self._state == SHUTDOWN:
                self._on_shutdown_complete(None)

        except Exception:
            self._transport.close()
            raise

    cdef _wakeup_waiter(self, exc=None):
        if (self._ssl_handshake_complete_waiter is not None and
                not self._ssl_handshake_complete_waiter.done()):
            if exc is not None:
                self._ssl_handshake_complete_waiter.set_exception(exc)
            else:
                self._ssl_handshake_complete_waiter.set_result(None)

    cdef _get_extra_info(self, name, default=None):
        if name == "ssl_object":
            return self._ssl_connection
        elif name in self._extra:
            return self._extra[name]
        elif self._transport is not None:
            return self._transport.get_extra_info(name, default)
        else:
            return default

    cdef _set_state(self, SSLProtocolState new_state):
        cdef bint allowed = False

        if self._loop.get_debug():
            _logger.debug("Change state to %s", SSLProtocolState(new_state).name)

        if new_state == UNWRAPPED:
            allowed = True

        elif self._state == UNWRAPPED and new_state == DO_HANDSHAKE:
            allowed = True

        elif self._state == DO_HANDSHAKE and new_state == WRAPPED:
            allowed = True

        elif self._state == WRAPPED and new_state == FLUSHING:
            allowed = True

        elif self._state == WRAPPED and new_state == SHUTDOWN:
            allowed = True

        elif self._state == FLUSHING and new_state == SHUTDOWN:
            allowed = True

        if allowed:
            self._state = new_state

        else:
            raise RuntimeError(
                'cannot switch state from {} to {}'.format(
                    self._state, new_state))

    # Handshake flow

    cdef _start_handshake(self):
        if self._loop.get_debug():
            _logger.debug("%r starts SSL handshake", self)
            self._handshake_start_time = self._loop.time()
        else:
            self._handshake_start_time = None

        self._set_state(DO_HANDSHAKE)

        # start handshake timeout count down
        self._handshake_timeout_handle = \
            self._loop.call_later(self._ssl_handshake_timeout,
                                  self._check_handshake_timeout)

        try:
            self._ssl_connection = SSLConnection(self._sslcontext, self._server_side, self._server_hostname)
        except Exception as ex:
            self._on_handshake_complete(ex)
        else:
            self._do_handshake()

    cdef _check_handshake_timeout(self):
        if self._state == DO_HANDSHAKE:
            msg = (
                f"SSL handshake is taking longer than "
                f"{self._ssl_handshake_timeout} seconds: "
                f"aborting the connection"
            )
            self._fatal_error(ConnectionAbortedError(msg))

    cdef _do_handshake(self):
        cdef int rc = SSL_do_handshake(self._ssl_connection.ssl_object)
        if rc == 1:
            self._on_handshake_complete(None)
            return

        cdef int ssl_error = SSL_get_error(self._ssl_connection.ssl_object, rc)
        if ssl_error in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
            self._process_outgoing()
            return

        self._on_handshake_complete(self._ssl_connection.make_exc_from_ssl_error("ssl handshake failed", ssl_error))

    cdef _on_handshake_complete(self, handshake_exc):
        if self._handshake_timeout_handle is not None:
            self._handshake_timeout_handle.cancel()
            self._handshake_timeout_handle = None

        try:
            if handshake_exc is None:
                self._set_state(WRAPPED)
            else:
                raise handshake_exc
        except Exception as exc:
            self._set_state(UNWRAPPED)
            if isinstance(exc, ssl.CertificateError):
                msg = 'SSL handshake failed on verifying the certificate'
            else:
                msg = 'SSL handshake failed'
            self._fatal_error(exc, msg)
            self._wakeup_waiter(exc)
            return

        if self._loop.get_debug():
            dt = self._loop.time() - self._handshake_start_time
            _logger.debug("%r: SSL handshake took %.1f ms", self, dt * 1e3)

        # Add extra info that becomes available after handshake.
        # TODO: add compression
        self._extra.update(
            peercert=self._ssl_connection.getpeercert(),
            cipher=self._ssl_connection.cipher(),
            compression=self._ssl_connection.compression()
        )
        if self._app_state == STATE_INIT:
            self._app_state = STATE_CON_MADE
            self._app_protocol.connection_made(self.get_app_transport())
        self._wakeup_waiter()

        # We should wakeup user code before sending the first data below. In
        # case of `start_tls()`, the user can only get the SSLTransport in the
        # wakeup callback, because `connection_made()` is not called again.
        # We should schedule the first data later than the wakeup callback so
        # that the user get a chance to e.g. check ALPN with the transport
        # before having to handle the first data.
        self._loop.call_soon(self._do_read)

    # Shutdown flow

    cdef _start_shutdown(self, object context=None):
        if self._state in (FLUSHING, SHUTDOWN, UNWRAPPED):
            return
        # we don't need the context for _abort or the timeout, because
        # TCP transport._force_close() should be able to call
        # connection_lost() in the right context
        if self._app_transport is not None:
            self._app_transport._closed = True
        if self._state == DO_HANDSHAKE:
            self._abort(None)
        else:
            self._set_state(FLUSHING)
            self._shutdown_timeout_handle = \
                self._loop.call_later(self._ssl_shutdown_timeout,
                                      lambda: self._check_shutdown_timeout())
            self._do_flush(context)

    cdef _check_shutdown_timeout(self):
        if self._state in (FLUSHING, SHUTDOWN):
            self._transport._force_close(
                asyncio.TimeoutError('SSL shutdown timed out'))

    cdef _do_read_into_void(self, object context):
        """Consume and discard incoming application data.

        If close_notify is received for the first time, call eof_received.
        """
        cdef:
            bytearray buffer = PyByteArray_FromStringAndSize(NULL, 16*1024)
            size_t bytes_read
            int rc = 1
        while rc == 1:
            rc = SSL_read_ex(self._ssl_connection.ssl_object,
                          PyByteArray_AS_STRING(buffer),
                          PyByteArray_GET_SIZE(buffer),
                          &bytes_read)

        cdef int ssl_error = SSL_get_error(self._ssl_connection.ssl_object, rc)
        if ssl_error in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
            return

        if ssl_error == SSL_ERROR_ZERO_RETURN:
            self._call_eof_received(context)
            return

        raise self._ssl_connection.make_exc_from_ssl_error("SSL_read_ex failed", ssl_error)

    cdef _do_flush(self, object context=None):
        """Flush the write backlog, discarding new data received.

        We don't send close_notify in FLUSHING because we still want to send
        the remaining data over SSL, even if we received a close_notify. Also,
        no application-level resume_writing() or pause_writing() will be called
        in FLUSHING, as we could fully manage the flow control internally.
        """
        try:
            self._do_read_into_void(context)
            self._do_write()
            self._process_outgoing()
        except Exception as ex:
            self._on_shutdown_complete(ex)
        else:
            if not self._get_ssl_write_buffer_size():
                self._set_state(SHUTDOWN)
                self._do_shutdown(context)

    cdef _do_shutdown(self, object context=None):
        """Send close_notify and wait for the same from the peer."""
        cdef int rc
        cdef int err_code
        try:
            # we must skip all application data (if any) before unwrap
            self._do_read_into_void(context)
            rc = SSL_shutdown(self._ssl_connection.ssl_object)
            if rc == 1:
                self._on_shutdown_complete(None)
                return

            if rc == 0:
                self._process_outgoing()
                return

            err_code = SSL_get_error(self._ssl_connection.ssl_object, rc)
            if err_code in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
                self._process_outgoing()
                return

            raise self._ssl_connection.make_exc_from_ssl_error("SSL_shutdown failed", err_code)
        except Exception as ex:
            self._on_shutdown_complete(ex)

    cdef _on_shutdown_complete(self, shutdown_exc):
        if self._shutdown_timeout_handle is not None:
            self._shutdown_timeout_handle.cancel()
            self._shutdown_timeout_handle = None

        # we don't need the context here because TCP transport.close() should
        # be able to call connection_made() in the right context
        if shutdown_exc:
            self._fatal_error(shutdown_exc, 'Error occurred during shutdown')
        else:
            self._transport.close()

    cdef _abort(self, exc):
        self._set_state(UNWRAPPED)
        if self._transport is not None:
            self._transport._force_close(exc)

    # Outgoing flow

    cdef write(self, data):
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it
        to be sent out asynchronously.
        """
        if not self._is_protocol_ready():
            return
        self._check_and_enqueue_appdata(data)
        self._flush_write_backlog()

    cdef write_mem(self, char* ptr, Py_ssize_t sz):
        if not self._is_protocol_ready():
            return

        if sz == 0:
            return

        data = PyMemoryView_FromMemory(ptr, sz, PyBUF_READ)
        self._write_backlog.append(data)
        self._flush_write_backlog()

    cdef writelines(self, list_of_data):
        """Write a list (or any iterable) of data bytes to the transport.

        The default implementation concatenates the arguments and
        calls write() on the result.
        """
        if not self._is_protocol_ready():
            return

        cdef Py_ssize_t backlog_len_before = len(self._write_backlog)

        try:
            for data in list_of_data:
                self._check_and_enqueue_appdata(data)
        except:
            # Remove already enqueued items on exception
            del self._write_backlog[backlog_len_before:]
            raise

        self._flush_write_backlog()

    cdef bint _is_protocol_ready(self) except -1:
        if self._state in (FLUSHING, SHUTDOWN, UNWRAPPED):
            if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                _logger.warning('SSL connection is closed')
            self._conn_lost += 1
            return False
        else:
            return True

    cdef _check_and_enqueue_appdata(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(f"data: expecting a bytes-like instance, "
                            f"got {type(data).__name__}")
        if not data:
            return

        self._write_backlog.append(data)

    cdef _flush_write_backlog(self):
        try:
            if self._state == WRAPPED and self._write_backlog:
                self._do_write()
                self._process_outgoing()

        except Exception as ex:
            self._fatal_error(ex, 'Fatal error on SSL protocol')

    cdef _do_write(self):
        """Do SSL write, consumes write backlog and fills outgoing BIO."""
        cdef char* data_ptr = NULL
        cdef Py_ssize_t data_len, data_len_init
        cdef size_t bytes_written
        cdef Py_ssize_t idx = 0
        cdef int rc = 1

        while idx < len(self._write_backlog):
            data = self._write_backlog[idx]
            aiofn_unpack_buffer(data, &data_ptr, &data_len)
            data_len_init = data_len
            while data_len > 0:
                rc = SSL_write_ex(self._ssl_connection.ssl_object, data_ptr, data_len, &bytes_written)
                if not rc:
                    break

                data_ptr += bytes_written
                data_len -= bytes_written

            if not rc:
                break

            idx += 1

        # Delete all data objects that were successfully sent
        del self._write_backlog[:idx]

        if rc:
            return

        cdef int ssl_error = SSL_get_error(self._ssl_connection.ssl_object, rc)

        # This is rare but still possible. SSL maybe refused to send data
        # because of re-negotiation. In such case we need to materialize
        # all objects in write_backlog. There could be memoryviews or bytearrays
        # containing high-level protocol write buffer.
        self._write_backlog[idx] = aiofn_maybe_copy_buffer_tail(data, data_ptr, data_len)
        for k in range(idx + 1, len(self._write_backlog)):
            self._write_backlog[k] = aiofn_maybe_copy_buffer(self._write_backlog[k])

        if ssl_error in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
            return

        raise self._ssl_connection.make_exc_from_ssl_error("SSL_write_ex failed", ssl_error)

    cdef _process_outgoing_backup(self):
        pass

    cdef _process_outgoing(self):
        # Don't call BIO_read as it needs some destination and copy memory.
        # Instead, get pointer to the data and data length, forward it to the
        # transport. Transport will copy it anyway if it can't be sent
        # immediately.
        #
        # Use BIO_seek instead of BIO_reset as it is more efficient.

        cdef char* ptr
        cdef long sz = BIO_get_mem_data(self._ssl_connection.outgoing, &ptr)
        if sz <= 0:
            return

        self._transport.write_mem(ptr, sz)
        if BIO_seek(self._ssl_connection.outgoing, sz) == -1:
            raise RuntimeError("BIO_seek(outgoing) failed")

    # Incoming flow

    cpdef _do_read(self):
        if self._state != WRAPPED:
            return
        try:
            if not self._app_reading_paused:
                if self._app_protocol_is_buffered:
                    self._do_read__buffered()
                else:
                    self._do_read__copied()
                if self._write_backlog:
                    self._do_write()
                self._process_outgoing()
        except Exception as ex:
            self._fatal_error(ex, 'Fatal error on SSL protocol')

    cdef _do_read__buffered(self):
        cdef:
            object app_buffer = call_get_buffer(self._app_protocol, -1)
            Py_ssize_t app_buffer_size = len(app_buffer)

        if app_buffer_size == 0:
            return

        cdef:
            size_t last_bytes_read
            Py_ssize_t total_bytes_read = 0
            Py_buffer pybuf

        PyObject_GetBuffer(app_buffer, &pybuf, PyBUF_SIMPLE | PyBUF_WRITABLE)
        cdef:
            char* buf_ptr = <char*>pybuf.buf
            Py_ssize_t buf_len = pybuf.len
            int rc = 0
        PyBuffer_Release(&pybuf)

        if buf_len == 0:
            raise ValueError("empty buffer provided by BufferedProtocol.get_buffer")

        while buf_len > 0:
            rc = SSL_read_ex(self._ssl_connection.ssl_object, buf_ptr, buf_len,
                        &last_bytes_read)
            if not rc:
                break
            buf_ptr += last_bytes_read
            buf_len -= last_bytes_read
            total_bytes_read += last_bytes_read

        cdef int last_error = SSL_get_error(self._ssl_connection.ssl_object, rc)

        if total_bytes_read > 0:
            call_buffer_updated(self._app_protocol, total_bytes_read)

        if buf_len == 0:
            self._loop.call_soon(self._do_read)
            return

        if last_error in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
            return

        if last_error == SSL_ERROR_ZERO_RETURN and SSL_get_shutdown(self._ssl_connection.ssl_object) == SSL_RECEIVED_SHUTDOWN:
            self._call_eof_received()
            self._start_shutdown()
            return

        raise self._ssl_connection.make_exc_from_ssl_error("SSL_read_ex failed", last_error)

    cdef _do_read__copied(self):
        cdef:
            size_t bytes_read
            list data = None
            bytes first_chunk = None, curr_chunk
            Py_ssize_t bytes_estimated
            int rc

        while True:
            bytes_estimated = (SSL_pending(self._ssl_connection.ssl_object) +
                               _bio_pending(self._ssl_connection.incoming))
            bytes_estimated = max(1024, bytes_estimated)

            curr_chunk = PyBytes_FromStringAndSize(NULL, bytes_estimated)
            rc = SSL_read_ex(self._ssl_connection.ssl_object,
                             PyBytes_AS_STRING(data),
                             PyBytes_GET_SIZE(data), &bytes_read)
            if not rc:
                break

            curr_chunk = aiofn_shrink_bytes(curr_chunk, bytes_read)

            if first_chunk is None:
                first_chunk = curr_chunk
            elif data is None:
                data = [first_chunk, curr_chunk]
            else:
                data.append(curr_chunk)

        cdef int last_error = SSL_get_error(self._ssl_connection.ssl_object, rc)

        if data is not None:
            call_data_received(self._app_protocol, b''.join(data))
        elif first_chunk is not None:
            call_data_received(self._app_protocol, first_chunk)

        if last_error in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
            return

        if last_error == SSL_ERROR_ZERO_RETURN and SSL_get_shutdown(self._ssl_connection.ssl_object) == SSL_RECEIVED_SHUTDOWN:
            # close_notify
            self._call_eof_received()
            self._start_shutdown()
            return

        raise self._ssl_connection.make_exc_from_ssl_error("SSL_read_ex failed", last_error)

    cdef _call_eof_received(self, object context=None):
        if self._app_state == STATE_CON_MADE:
            self._app_state = STATE_EOF
            try:
                if context is None:
                    # If the caller didn't provide a context, we assume the
                    # caller is already in the right context, which is usually
                    # inside the upstream callbacks like buffer_updated()
                    keep_open = self._app_protocol.eof_received()
                else:
                    keep_open = _run_in_context(
                        context, self._app_protocol.eof_received,
                    )
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as ex:
                self._fatal_error(ex, 'Error calling eof_received()')
            else:
                if keep_open:
                    _logger.warning('returning true from eof_received() '
                                       'has no effect when using ssl')

    # Flow control for reads to APP socket

    cdef _pause_reading(self):
        self._app_reading_paused = True
        self._transport.pause_reading()

    cdef _resume_reading(self, object context):
        if self._app_reading_paused:
            self._app_reading_paused = False
            if self._state == WRAPPED:
                self._loop.call_soon(self._do_read)
        self._transport.resume_reading()

    # Flow control for writes to SSL socket

    cpdef pause_writing(self):
        """Called when the low-level transport's buffer goes over
        the high-water mark.
        """
        self._app_protocol.pause_writing()

    cpdef resume_writing(self):
        """Called when the low-level transport's buffer drains below
        the low-water mark.
        """
        self._app_protocol.resume_writing()

    cdef Py_ssize_t _get_ssl_write_buffer_size(self):
        cdef Py_ssize_t bytes_in_backlog = 0
        for data in self._write_backlog:
            bytes_in_backlog += len(data)
        return bytes_in_backlog + _bio_pending(self._ssl_connection.outgoing)

    cdef Py_ssize_t _get_write_buffer_size(self):
        return self._get_ssl_write_buffer_size() + self._transport.get_write_buffer_size()

    cdef _get_write_buffer_limits(self):
        return self._transport.get_write_buffer_limits()

    cdef _set_write_buffer_limits(self, high=None, low=None):
        return self._transport.set_write_buffer_limits(high, low)

    cdef _fatal_error(self, exc, message='Fatal error on transport'):
        if self._app_transport:
            self._app_transport._force_close(exc)
        elif self._transport:
            self._transport._force_close(exc)

        if isinstance(exc, OSError):
            if self._loop.get_debug():
                _logger.debug("%r: %s", self, message, exc_info=True)
        elif not isinstance(exc, asyncio.CancelledError):
            self._loop.call_exception_handler({
                'message': message,
                'exception': exc,
                'transport': self._transport,
                'protocol': self,
            })
