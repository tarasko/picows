import ssl

from cpython.unicode cimport PyUnicode_FromStringAndSize, PyUnicode_FromString
from cpython.ref cimport PyObject
from cpython.bytes cimport PyBytes_CheckExact, PyBytes_AS_STRING, PyBytes_GET_SIZE, PyBytes_FromStringAndSize, _PyBytes_Resize
from cpython.bytearray cimport PyByteArray_CheckExact, PyByteArray_AS_STRING, PyByteArray_GET_SIZE
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.ref cimport Py_INCREF, Py_DECREF

# cdef extern from *:
# We intentionally mirror ONLY the initial prefix of CPython's PySSLContext:
# PyObject_HEAD + SSL_CTX *ctx;
# This is NOT ABI-stable and may break across Python versions/build options.

ctypedef struct PySSLContextHack:
    PyObject ob_base
    SSL_CTX *ctx


cdef SSL_CTX* get_ssl_ctx_ptr(object py_ctx) except NULL:
    # Minimal runtime sanity check (still not foolproof)
    if not isinstance(py_ctx, ssl.SSLContext):
        raise TypeError("expected ssl.SSLContext")

    # Layout-cast hack:
    return (<PySSLContextHack*> <PyObject*> py_ctx).ctx


cdef int _log_cb(const char* str, size_t len, void* u) noexcept nogil:
    with gil:
        logger = <object><PyObject*>u
        err_str = PyUnicode_FromStringAndSize(str, len)
        logger.error(err_str)


cdef log_ssl_error_queue(logger):
    cdef void* u = <PyObject*>logger
    ERR_print_errors_cb(&_log_cb, u)


cdef unsigned long get_last_error():
    cdef unsigned long err_code = ERR_peek_last_error()
    ERR_clear_error()
    return err_code


cdef make_ssl_exc(unsigned long err_code, str reason):
    # TODO:
    # Make ssl.CertificateError on certificate verification failures

    cdef char err_string[256]
    ERR_error_string_n(err_code, err_string, sizeof(err_string))
    raise ssl.SSLError(f"{reason}: ec={err_code}, {err_string.decode()}")


cdef raise_last_error(str reason):
    cdef unsigned long err_code = get_last_error()
    assert err_code != 0, "raise_last_error called and ERR_peek_last_error() == 0"
    raise make_ssl_exc(err_code, reason)


cdef unpack_bytes_like(object bytes_like_obj, char** msg_ptr_out, Py_ssize_t* msg_size_out):
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


cdef Py_ssize_t bio_pending(BIO* bio):
    cdef int pending = BIO_pending(bio)
    if pending < 0:
        raise_last_error("unable to get pending len from BIO")
    return pending


cdef Py_ssize_t ssl_object_pending(SSL* bio):
    cdef int pending = SSL_pending(bio)
    if pending < 0:
        raise_last_error("unable to get pending len from SSL object")
    return pending


cdef bytes shrink_bytes(bytes obj, Py_ssize_t new_size):
    cdef PyObject* raw = <PyObject*>obj
    Py_INCREF(obj)
    _PyBytes_Resize(&raw, new_size)
    cdef bytes maybe_new_obj = <bytes>raw
    Py_DECREF(obj)
    return maybe_new_obj


cdef class SSLConnection:
    def __init__(self, logger, ssl_context, bint is_server, str server_hostname):
        ERR_clear_error()

        self.ssl_ctx = get_ssl_ctx_ptr(ssl_context)
        self.incoming = BIO_new(BIO_s_mem())
        self.outgoing = BIO_new(BIO_s_mem())
        self.ssl_object = SSL_new(self.ssl_ctx)
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

        if server_hostname is not None:
            self._configure_hostname(logger, ssl_context, server_hostname)

    def __dealloc__(self):
        # Free SSL and its BIO
        SSL_free(self.ssl_object)

    cdef _configure_hostname(self, logger, ssl_context, str server_hostname):
        if not server_hostname or server_hostname.startswith("."):
            raise ValueError("server_hostname cannot be an empty string or start with a leading dot.")

        cdef bytes server_hostname_b = server_hostname.encode()
        cdef char* server_hostname_ptr = PyBytes_AS_STRING(server_hostname_b)

        cdef ASN1_OCTET_STRING* ip = a2i_IPADDRESS(PyBytes_AS_STRING(server_hostname_b))
        if ip == NULL:
            ERR_clear_error()

        cdef X509_VERIFY_PARAM* ssl_verification_params
        try:
            # Only send SNI extension for non-IP hostnames
            if ip == NULL:
                if not SSL_set_tlsext_host_name(self.ssl_object, server_hostname_ptr):
                    log_ssl_error_queue(logger)
                    ERR_clear_error()
                    raise ssl.SSLError("SSL_set_tlsext_host_name failed")

            if ssl_context.check_hostname:
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

    # TODO: I don't think people would need this.
    # For now I return None but if somebody asks can be made compatible with
    # python implementation
    cdef str compression(self):
        return None

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
            raise_last_error("ssl handshake is not done yet")

        cdef X509* peer_cert = SSL_get_peer_certificate(self.ssl_object)
        if peer_cert == NULL:
            return None

        cdef int verification = SSL_CTX_get_verify_mode(self.ssl_ctx)
        try:
            return self._decode_certificate(peer_cert) if verification & SSL_VERIFY_PEER else dict()
        finally:
            X509_free(peer_cert)

    # TODO: Implement this
    cdef _decode_certificate(self, X509* certificate):
        cdef dict retval = dict()
        return retval
