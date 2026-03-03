#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "static_mem_bio.h"

#include <openssl/crypto.h>

typedef struct static_mem_bio_state_s {
    unsigned char *begin;
    unsigned char *end;
    unsigned char *rptr;
    unsigned char *wptr;
    int eof_return;
} static_mem_bio_state_t;

static BIO_METHOD *g_static_mem_bio_method = NULL;
static CRYPTO_ONCE g_static_mem_bio_once = CRYPTO_ONCE_STATIC_INIT;

static size_t
static_mem_avail(const static_mem_bio_state_t *st) {
    return (size_t)(st->wptr - st->rptr);
}

static size_t
static_mem_space(const static_mem_bio_state_t *st) {
    return (size_t)(st->end - st->wptr);
}

static int
static_mem_bio_create(BIO *bio) {
    BIO_set_init(bio, 0);
    BIO_set_data(bio, NULL);
    BIO_set_shutdown(bio, 0);
    return 1;
}

static int
static_mem_bio_destroy(BIO *bio) {
    static_mem_bio_state_t *st;

    if (bio == NULL) {
        return 0;
    }

    st = (static_mem_bio_state_t *)BIO_get_data(bio);
    if (st != NULL) {
        OPENSSL_free(st);
        BIO_set_data(bio, NULL);
    }
    BIO_set_init(bio, 0);
    return 1;
}

static int
static_mem_bio_read(BIO *bio, char *out, int outl) {
    static_mem_bio_state_t *st;
    size_t avail;
    size_t n;

    if (out == NULL || outl <= 0) {
        return 0;
    }

    st = (static_mem_bio_state_t *)BIO_get_data(bio);
    if (st == NULL || !BIO_get_init(bio)) {
        return 0;
    }

    BIO_clear_retry_flags(bio);
    avail = static_mem_avail(st);
    if (avail == 0) {
        BIO_set_retry_read(bio);
        return st->eof_return;
    }

    n = avail < (size_t)outl ? avail : (size_t)outl;
    memcpy(out, st->rptr, n);
    st->rptr += n;

    if (st->rptr == st->wptr) {
        st->rptr = st->begin;
        st->wptr = st->begin;
    }

    if (n > (size_t)INT_MAX) {
        return INT_MAX;
    }
    return (int)n;
}

static int
static_mem_bio_write(BIO *bio, const char *in, int inl) {
    static_mem_bio_state_t *st;
    size_t n;
    size_t space;
    size_t avail;

    if (in == NULL || inl <= 0) {
        return 0;
    }

    st = (static_mem_bio_state_t *)BIO_get_data(bio);
    if (st == NULL || !BIO_get_init(bio)) {
        return 0;
    }

    BIO_clear_retry_flags(bio);
    space = static_mem_space(st);
    if (space < (size_t)inl && st->rptr != st->begin) {
        avail = static_mem_avail(st);
        memmove(st->begin, st->rptr, avail);
        st->rptr = st->begin;
        st->wptr = st->begin + avail;
        space = static_mem_space(st);
    }

    if (space == 0) {
        BIO_set_retry_write(bio);
        return -1;
    }

    n = space < (size_t)inl ? space : (size_t)inl;
    memcpy(st->wptr, in, n);
    st->wptr += n;

    if (n < (size_t)inl) {
        BIO_set_retry_write(bio);
    }

    if (n > (size_t)INT_MAX) {
        return INT_MAX;
    }
    return (int)n;
}

static int
static_mem_bio_puts(BIO *bio, const char *str) {
    (void)bio;
    (void)str;
    return -2;
}

static int
static_mem_bio_gets(BIO *bio, char *buf, int size) {
    (void)bio;
    (void)buf;
    (void)size;
    return -2;
}

static long
static_mem_bio_ctrl(BIO *bio, int cmd, long num, void *ptr) {
    static_mem_bio_state_t *st;
    size_t avail;

    st = (static_mem_bio_state_t *)BIO_get_data(bio);
    if (st == NULL && cmd != BIO_CTRL_RESET) {
        return 0;
    }

    switch (cmd) {
        case BIO_CTRL_RESET:
            if (st != NULL) {
                st->rptr = st->begin;
                st->wptr = st->begin;
            }
            return 1;
        case BIO_CTRL_EOF:
            return st->wptr == st->rptr;
        case BIO_CTRL_INFO:
            if (ptr != NULL) {
                *(char **)ptr = (char *)st->rptr;
            }
            avail = static_mem_avail(st);
            return avail > (size_t)LONG_MAX ? LONG_MAX : (long)avail;
        case BIO_CTRL_PENDING:
            avail = static_mem_avail(st);
            return avail > (size_t)LONG_MAX ? LONG_MAX : (long)avail;
        case BIO_CTRL_WPENDING:
            return 0;
        case BIO_CTRL_FLUSH:
            return 1;
        case BIO_C_FILE_SEEK:
            (void)num;
            return -2;
        case BIO_C_FILE_TELL:
            return 0;
        case BIO_C_SET_BUF_MEM_EOF_RETURN:
            st->eof_return = (int)num;
            return 1;
        case BIO_C_SET_NBIO:
            st->eof_return = num ? -1 : 0;
            return 1;
        case BIO_CTRL_DUP:
            return 1;
        default:
            return 0;
    }
}

int
BIO_static_mem_get_write_buf(BIO *bio, char **pp, size_t *space) {
    static_mem_bio_state_t *st;
    size_t avail;

    if (bio == NULL || pp == NULL || space == NULL) {
        return 0;
    }

    st = (static_mem_bio_state_t *)BIO_get_data(bio);
    if (st == NULL || !BIO_get_init(bio)) {
        return 0;
    }

    if (st->rptr != st->begin && st->wptr == st->end) {
        avail = static_mem_avail(st);
        memmove(st->begin, st->rptr, avail);
        st->rptr = st->begin;
        st->wptr = st->begin + avail;
    }

    *pp = (char *)st->wptr;
    *space = static_mem_space(st);
    return 1;
}

int
BIO_static_mem_produce(BIO *bio, size_t nbytes) {
    static_mem_bio_state_t *st;
    size_t space;

    if (bio == NULL) {
        return -1;
    }

    st = (static_mem_bio_state_t *)BIO_get_data(bio);
    if (st == NULL || !BIO_get_init(bio)) {
        return -1;
    }

    space = static_mem_space(st);
    if (nbytes > space) {
        return -1;
    }

    st->wptr += nbytes;
    return 1;
}

int
BIO_static_mem_consume(BIO *bio, size_t nbytes) {
    static_mem_bio_state_t *st;
    size_t avail;

    if (bio == NULL) {
        return -1;
    }

    st = (static_mem_bio_state_t *)BIO_get_data(bio);
    if (st == NULL || !BIO_get_init(bio)) {
        return -1;
    }

    avail = static_mem_avail(st);
    if (nbytes > avail) {
        return -1;
    }

    st->rptr += nbytes;
    if (st->rptr == st->wptr) {
        st->rptr = st->begin;
        st->wptr = st->begin;
    }
    return 1;
}

static void static_mem_bio_init_once(void) {
    BIO_METHOD *m;

    m = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "static_mem");
    if (m == NULL) {
        return;
    }

    if (!BIO_meth_set_write(m, static_mem_bio_write) ||
        !BIO_meth_set_read(m, static_mem_bio_read) ||
        !BIO_meth_set_puts(m, static_mem_bio_puts) ||
        !BIO_meth_set_gets(m, static_mem_bio_gets) ||
        !BIO_meth_set_ctrl(m, static_mem_bio_ctrl) ||
        !BIO_meth_set_create(m, static_mem_bio_create) ||
        !BIO_meth_set_destroy(m, static_mem_bio_destroy)) {
        BIO_meth_free(m);
        return;
    }

    g_static_mem_bio_method = m;
}

const BIO_METHOD* BIO_s_static_mem(void) {
    if (!CRYPTO_THREAD_run_once(&g_static_mem_bio_once,
                                static_mem_bio_init_once)) {
        return NULL;
    }
    return g_static_mem_bio_method;
}

BIO *
BIO_new_static_mem(void *buf, size_t cap) {
    BIO *bio;
    static_mem_bio_state_t *st;
    const BIO_METHOD *meth;

    if (buf == NULL || cap == 0) {
        return NULL;
    }

    meth = BIO_s_static_mem();
    if (meth == NULL) {
        return NULL;
    }

    bio = BIO_new(meth);
    if (bio == NULL) {
        return NULL;
    }

    st = OPENSSL_zalloc(sizeof(*st));
    if (st == NULL) {
        BIO_free(bio);
        return NULL;
    }

    st->begin = (unsigned char *)buf;
    st->end = st->begin + cap;
    st->rptr = st->begin;
    st->wptr = st->begin;
    st->eof_return = 0;

    BIO_set_data(bio, st);
    BIO_set_init(bio, 1);
    return bio;
}
