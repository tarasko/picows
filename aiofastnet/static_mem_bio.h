#ifndef AIOFASTNET_STATIC_MEM_BIO_H
#define AIOFASTNET_STATIC_MEM_BIO_H

#include <stddef.h>

#include <openssl/bio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Fixed-capacity, non-owning memory BIO.
 *
 * Purpose:
 * - Provide a bounded BIO backed by caller-owned memory.
 * - Enable explicit producer/consumer style buffer management for SSL I/O.
 * - Avoid dynamic BIO growth and make capacity limits predictable.
 *
 * Public API:
 * - BIO_s_static_mem(void):
 *   Returns BIO_METHOD singleton for this BIO type.
 * - BIO_new_static_mem(void *buf, size_t cap):
 *   Creates BIO over caller-provided storage [buf, cap).
 * - BIO_static_mem_get_write_buf(BIO *bio, char **pp, size_t *space):
 *   Returns contiguous writable tail and available capacity.
 * - BIO_static_mem_produce(BIO *bio, size_t nbytes):
 *   Publishes bytes written into the writable tail.
 * - BIO_static_mem_consume(BIO *bio, size_t nbytes):
 *   Consumes readable bytes from the head.
 *
 * Supported operations:
 * - read/write, pending/info/eof/flush/reset.
 * - partial nonblocking control support.
 * - dup (returns success, no deep clone).
 *
 * Unsupported operations:
 * - puts/gets.
 * - seek/tell style file controls for consume semantics.
 *   Use BIO_static_mem_consume() explicitly instead.
 *
 * Ownership:
 * - BIO does NOT own caller buffer and never frees it.
 * - BIO owns only internal state metadata.
 */
const BIO_METHOD *BIO_s_static_mem(void);
BIO *BIO_new_static_mem(void *buf, size_t cap);
int BIO_static_mem_get_write_buf(BIO *bio, char **pp, size_t *space);
int BIO_static_mem_produce(BIO *bio, size_t nbytes);
int BIO_static_mem_consume(BIO *bio, size_t nbytes);

#ifdef __cplusplus
}
#endif

#endif
