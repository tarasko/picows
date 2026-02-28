from libc cimport errno

from cpython.bytes cimport (
    PyBytes_CheckExact, PyBytes_AS_STRING, PyBytes_GET_SIZE, _PyBytes_Resize,
    PyBytes_FromStringAndSize
)

from cpython.bytearray cimport (
    PyByteArray_CheckExact, PyByteArray_AS_STRING, PyByteArray_GET_SIZE
)

from cpython.memoryview cimport PyMemoryView_FromMemory

from cpython.buffer cimport (
    PyObject_GetBuffer, PyBuffer_Release, PyBUF_SIMPLE, PyBUF_READ
)

from cpython.object cimport (
    PyObject
)

from cpython.ref cimport (
    Py_INCREF, Py_DECREF
)

cdef extern from * nogil:
    """
#include <errno.h>

#ifndef ESHUTDOWN
    #define ESHUTDOWN EPIPE
#endif

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)
    #define __WINDOWS__
    #define AIOFN_IS_WINDOWS 1
#else
    #define AIOFN_IS_WINDOWS 0
#endif

#ifdef __APPLE__
    #define AIOFN_IS_APPLE 1
#else
    #define AIOFN_IS_APPLE 0
#endif

#ifdef __linux__
    #define AIOFN_IS_LINUX 1
#else
    #define AIOFN_IS_LINUX 0
#endif

#ifdef __WINDOWS__
    #include <winsock2.h>
    #define AIOFN_EAGAIN WSAEWOULDBLOCK
    #define AIOFN_EWOULDBLOCK WSAEWOULDBLOCK
    int aiofn_get_last_error() { return WSAGetLastError(); }
    void aiofn_set_exc_from_error(int error) {
        PyErr_SetExcFromWindowsErr(PyExc_OSError, error);
    }
#else
    #include <sys/types.h>
    #include <sys/socket.h>

    #define AIOFN_EAGAIN EAGAIN
    #ifdef EWOULDBLOCK
        #define AIOFN_EWOULDBLOCK EWOULDBLOCK
    #else
        #define AIOFN_EWOULDBLOCK EGAIN
    #endif

    int aiofn_get_last_error() { return errno; }
    void aiofn_set_exc_from_error(int) {
        PyErr_SetFromErrno(PyExc_OSError);
    }
#endif
    """

    cdef bint AIOFN_IS_APPLE
    cdef bint AIOFN_IS_LINUX
    cdef bint AIOFN_IS_WINDOWS
    cdef int AIOFN_EWOULDBLOCK
    cdef int AIOFN_EAGAIN

    int aiofn_get_last_error()
    void aiofn_set_exc_from_error(int error)

    ssize_t recv(int sockfd, void* buf, size_t len, int flags)
    ssize_t send(int sockfd, const void* buf, size_t len, int flags)


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


cdef inline aiofn_unpack_buffer(object bytes_like_obj, char** ptr_out, Py_ssize_t* size_out):
    cdef Py_buffer pybuf

    if PyBytes_CheckExact(bytes_like_obj):
        ptr_out[0] = PyBytes_AS_STRING(bytes_like_obj)
        size_out[0] = PyBytes_GET_SIZE(bytes_like_obj)
    elif PyByteArray_CheckExact(bytes_like_obj):
        ptr_out[0] = PyByteArray_AS_STRING(bytes_like_obj)
        size_out[0] = PyByteArray_GET_SIZE(bytes_like_obj)
    elif bytes_like_obj is None:
        ptr_out[0] = NULL
        size_out[0] = 0
    else:
        PyObject_GetBuffer(bytes_like_obj, &pybuf, PyBUF_SIMPLE)
        ptr_out[0] = <char*>pybuf.buf
        size_out[0] = pybuf.len
        # We can already release because we still keep the reference to the message
        PyBuffer_Release(&pybuf)


cdef inline bytes aiofn_shrink_bytes(bytes obj, Py_ssize_t new_size):
    cdef PyObject* raw = <PyObject*>obj
    Py_INCREF(obj)
    _PyBytes_Resize(&raw, new_size)
    cdef bytes maybe_new_obj = <bytes>raw
    Py_DECREF(obj)
    return maybe_new_obj


cdef inline object aiofn_maybe_copy_buffer_tail(object buffer, Py_ssize_t tail_pos):
    cdef Py_ssize_t buffer_size
    # Do not copy bytes content, it is safe to make a memory view
    if PyBytes_CheckExact(buffer):
        buffer_size = PyBytes_GET_SIZE(buffer)
        return PyMemoryView_FromMemory(
            PyBytes_AS_STRING(buffer) + tail_pos,
            PyBytes_GET_SIZE(buffer) - tail_pos,
            PyBUF_READ
        )

    # Always copy bytearray, bytearray may be used as a permanent write buffer
    # in the upper level protocol.
    if PyByteArray_CheckExact(buffer):
        buffer_size = PyByteArray_GET_SIZE(buffer)
        return PyBytes_FromStringAndSize(
            PyByteArray_AS_STRING(buffer) + tail_pos,
            PyByteArray_GET_SIZE(buffer) - tail_pos
        )

    # For memoryview we check if it is made from bytes object.
    # In such case it is safe to create another memoryview
    cdef Py_buffer pybuf
    PyObject_GetBuffer(buffer, &pybuf, PyBUF_SIMPLE)
    cdef:
        bint is_bytes = (<PyObject*>pybuf.obj != NULL) and PyBytes_CheckExact(pybuf.obj)
        char* buffer_ptr = <char*>pybuf.buf
    buffer_size = pybuf.len
    PyBuffer_Release(&pybuf)

    if is_bytes:
        return memoryview(buffer)[tail_pos:]
    else:
        return PyBytes_FromStringAndSize(buffer_ptr + tail_pos, buffer_size - tail_pos)