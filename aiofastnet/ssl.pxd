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

    ctypedef struct SSL_CIPHER:
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
    long BIO_get_mem_data(BIO *b, char** pp)

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
    int SSL_do_handshake(SSL *ssl)
    int SSL_accept(SSL *ssl)
    int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
    int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)
    int SSL_shutdown(SSL *ssl)
    int SSL_get_shutdown(const SSL *ssl)
    int SSL_get_error(const SSL *ssl, int ret)
    long SSL_get_verify_result(const SSL *ssl)

    const SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl)
    const char *SSL_CIPHER_get_name(const SSL_CIPHER *cipher)
    const char *SSL_CIPHER_get_version(const SSL_CIPHER *cipher)
    int SSL_CIPHER_get_bits(const SSL_CIPHER *cipher, int *alg_bits)

    X509 *SSL_get_peer_certificate(const SSL *ssl)
    X509_VERIFY_PARAM *SSL_get0_param(SSL *ssl)
    X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx)

    unsigned int X509_VERIFY_PARAM_get_hostflags(const X509_VERIFY_PARAM *param)
    void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *param, unsigned int flags)
    int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param, const char *name, size_t namelen)
    int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *param, const unsigned char *ip, size_t iplen)
    const X509_NAME *X509_get_subject_name(const X509 *x)
    const char *X509_verify_cert_error_string(long n)
    void X509_free(X509 *a)


cdef extern from "openssl/err.h" nogil:
    enum:
        ERR_LIB_SSL
        ERR_LIB_X509
        ERR_LIB_X509V3
        ERR_LIB_PEM
        ERR_LIB_ASN1
        ERR_LIB_EVP
        ERR_LIB_BIO
        ERR_LIB_SYS
        ERR_LIB_PKCS12
        ERR_LIB_PKCS7
        ERR_LIB_RAND
        ERR_LIB_CONF
        ERR_LIB_ENGINE
        ERR_LIB_OCSP
        ERR_LIB_UI
        ERR_LIB_TS
        ERR_LIB_CMS
        ERR_LIB_CRYPTO

    enum:
        SSL_R_CERTIFICATE_VERIFY_FAILED

    enum:
        X509_V_ERR_HOSTNAME_MISMATCH
        X509_V_ERR_IP_ADDRESS_MISMATCH

    unsigned long ERR_peek_last_error()
    void ERR_clear_error()
    void ERR_error_string_n(unsigned long e, char *buf, size_t len)
    const char* ERR_lib_error_string(unsigned long e)
    const char* ERR_reason_error_string(unsigned long e)
    void ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
                             void *u)
    int ERR_GET_LIB(unsigned long e)
    int ERR_GET_REASON(unsigned long e)


cdef extern from "openssl/asn1.h" nogil:
    ctypedef struct ASN1_OCTET_STRING:
        pass

    void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a)
    const unsigned char *ASN1_STRING_get0_data(const ASN1_OCTET_STRING *x)
    int ASN1_STRING_length(ASN1_OCTET_STRING *x);


cdef extern from "openssl/x509v3.h" nogil:
    ASN1_OCTET_STRING* a2i_IPADDRESS(const char *ipasc)


cdef class SSLConnection:
    cdef:
        object logger
        object ssl_ctx_py
        SSL_CTX* ssl_ctx
        BIO* incoming
        BIO* outgoing
        SSL* ssl_object
        str server_hostname

    cdef inline make_exc_from_ssl_error(self, str descr, int err_code)
    cdef inline dict getpeercert(self)
    cdef inline tuple cipher(self)
    cdef inline str compression(self)
    cdef inline _decode_certificate(self, X509* certificate)
    cdef inline _configure_hostname(self)


cdef Py_ssize_t bio_pending(BIO* bio)

