from libc.stdio cimport FILE, stderr, stdout


cdef extern from "openssl/ssl.h" nogil:
    ctypedef struct SSL_CTX:
        pass

    ctypedef struct SSL:
        pass

    ctypedef struct BIO_METHOD:
        pass

    ctypedef struct BIO:
        pass

    ctypedef struct X509:
        pass

    ctypedef struct X509_NAME:
        pass

    ctypedef struct X509_VERIFY_PARAM:
        pass

    enum:
        SSL_ERROR_NONE
        SSL_ERROR_SSL
        SSL_ERROR_WANT_WRITE
        SSL_ERROR_WANT_READ
        SSL_ERROR_ZERO_RETURN
        SSL_ERROR_SYSCALL
        SSL_ERROR_CERTIFICATE_VERIFY_FAILED

    enum:
        OPENSSL_VERSION_NUMBER
        SSL_VERIFY_PEER
        SSL_RECEIVED_SHUTDOWN
        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
        SSL_MODE_AUTO_RETRY

    const BIO_METHOD *BIO_s_mem()

    int SSL_CTX_get_verify_mode(const SSL_CTX *ctx)

    BIO *BIO_new(const BIO_METHOD *type)
    int BIO_free(BIO *a)
    int BIO_read(BIO *b, void *data, int dlen)
    int BIO_write(BIO *b, const void *data, int dlen)
    int BIO_pending(BIO *b)
    long BIO_set_nbio(BIO *b, long n)

    SSL *SSL_new(SSL_CTX *ctx)
    void SSL_free(SSL *ssl)
    void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio)
    void SSL_set_accept_state(SSL *ssl)
    void SSL_set_connect_state(SSL *ssl)
    long SSL_set_mode(SSL *ssl, long mode)
    int SSL_set_tlsext_host_name(const SSL *s, const char *name)
    int SSL_is_server(const SSL *ssl)
    int SSL_get_error(const SSL *ssl, int ret)
    int SSL_in_init(const SSL *s)
    int SSL_in_before(const SSL *s)
    int SSL_is_init_finished(const SSL *s)
    int SSL_pending(const SSL *ssl)

    int SSL_in_connect_init(SSL *s)
    int SSL_in_accept_init(SSL *s)
    int SSL_accept(SSL *ssl)
    int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
    int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)
    int SSL_shutdown(SSL *ssl)
    int SSL_get_shutdown(const SSL *ssl)
    int SSL_get_error(const SSL *ssl, int ret)

    int SSL_do_handshake(SSL *ssl)

    X509 *SSL_get_peer_certificate(const SSL *ssl)
    X509_VERIFY_PARAM *SSL_get0_param(SSL *ssl)
    X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx)

    unsigned int X509_VERIFY_PARAM_get_hostflags(const X509_VERIFY_PARAM *param)
    void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *param, unsigned int flags)
    int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param, const char *name, size_t namelen)
    int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *param, const unsigned char *ip, size_t iplen)
    const X509_NAME *X509_get_subject_name(const X509 *x)
    void X509_free(X509 *a)


cdef extern from "openssl/err.h" nogil:
    unsigned long ERR_peek_last_error()
    void ERR_clear_error()
    void ERR_error_string_n(unsigned long e, char *buf, size_t len)
    void ERR_print_errors_fp(FILE *fp)
    void ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
                             void *u)


cdef extern from "openssl/asn1.h" nogil:
    ctypedef struct ASN1_OCTET_STRING:
        pass

    void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a)
    const unsigned char *ASN1_STRING_get0_data(const ASN1_OCTET_STRING *x)
    int ASN1_STRING_length(ASN1_OCTET_STRING *x);


cdef extern from "openssl/x509v3.h" nogil:
    ASN1_OCTET_STRING* a2i_IPADDRESS(const char *ipasc)


cdef SSL_CTX* get_ssl_ctx_ptr(object py_ctx) except NULL
cdef unsigned long get_last_error()
cdef make_ssl_exc(unsigned long err_code, str reason)
cdef raise_last_error(str reason)
cdef log_ssl_error_queue(logger)

# TODO: Keep it here until we find a better place for this function
cdef unpack_bytes_like(object bytes_like_obj, char** msg_ptr_out, Py_ssize_t* msg_size_out)

cdef bytes shrink_bytes(bytes obj, Py_ssize_t new_size)
cdef Py_ssize_t bio_pending(BIO* bio)
cdef Py_ssize_t ssl_object_pending(SSL* bio)
cdef bytes read_from_bio(BIO* bio)


cdef class SSLConnection:
    cdef:
        SSL_CTX* ssl_ctx
        BIO* incoming
        BIO* outgoing
        SSL* ssl_object

    cdef inline dict getpeercert(self)
    cdef inline _decode_certificate(self, X509* certificate)
    cdef inline _configure_hostname(self, logger, ssl_context, str server_hostname)