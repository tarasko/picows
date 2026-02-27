import ssl

from cpython.unicode cimport PyUnicode_FromStringAndSize, PyUnicode_FromString
from cpython.ref cimport PyObject
from cpython.bytes cimport PyBytes_CheckExact, PyBytes_AS_STRING, PyBytes_GET_SIZE, _PyBytes_Resize, PyBytes_FromString
from cpython.bytearray cimport PyByteArray_CheckExact, PyByteArray_AS_STRING, PyByteArray_GET_SIZE
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.ref cimport Py_INCREF, Py_DECREF

_lib_to_name = {
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


cdef class SSLConnection:
    def __init__(self, logger, ssl_context, bint is_server, str server_hostname):
        ERR_clear_error()

        self.logger = logger
        self.ssl_ctx_py = ssl_context
        self.ssl_ctx = get_ssl_ctx_ptr(ssl_context)
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
            return make_exc_from_last_error(descr, self.server_hostname, self.ssl_object, self.logger)
        else:
            return ssl.SSLError(f"{descr}, unknown error_code={err_code}")

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
                    log_ssl_error_queue(self.logger)
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
            raise ssl.SSLError("SSL_is_init_finished failed")

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


cdef make_exc_from_last_error(str descr, server_hostname=None, SSL* ssl_object=NULL, logger=None):
    cdef unsigned long last_error = get_last_error()
    cdef int lib = ERR_GET_LIB(last_error)
    cdef int reason = ERR_GET_REASON(last_error)

    if logger is not None:
        log_ssl_error_queue(logger)

    lib_name = _lib_to_name.get(lib, "UNKNOWN")
    reason_name = PyUnicode_FromString(ERR_reason_error_string(last_error))
    reason_name = reason_name.upper().replace(" ", "_")

    if reason == SSL_R_CERTIFICATE_VERIFY_FAILED:
        assert server_hostname is not None
        assert ssl_object != NULL
        verify_code = SSL_get_verify_result(ssl_object)
        if verify_code == X509_V_ERR_HOSTNAME_MISMATCH:
            txt = f"Hostname mismatch, certificate is not valid for '{server_hostname}'"
        elif verify_code == X509_V_ERR_IP_ADDRESS_MISMATCH:
            txt = f"IP address mismatch, certificate is not valid for '{server_hostname}'"
        else:
            verify_str = X509_verify_cert_error_string(verify_code)
            txt = PyUnicode_FromString(verify_str) if verify_str != NULL else ""
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
        raise make_exc_from_last_error("unable to get pending len from BIO")
    return pending


cdef bytes shrink_bytes(bytes obj, Py_ssize_t new_size):
    cdef PyObject* raw = <PyObject*>obj
    Py_INCREF(obj)
    _PyBytes_Resize(&raw, new_size)
    cdef bytes maybe_new_obj = <bytes>raw
    Py_DECREF(obj)
    return maybe_new_obj

