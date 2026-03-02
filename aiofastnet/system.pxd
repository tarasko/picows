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

    // Memory layout is compatible with WSABUF
    typedef struct
    {
        ULONG iov_len;
        CHAR* iov_base;
    } aiofn_iovec;

    Py_ssize_t aiofn_writev_sys(int fd, aiofn_iovec* iov, int iovcnt)
    {
        DWORD bytes_sent = 0;
        int rc = WSASend(fd, (LPWSABUF)iov, iovcnt, &bytes_sent, 0, NULL, NULL);
        return rc == SOCKET_ERROR ? -1 : bytes_sent;
    }

#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/uio.h>

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

    typedef struct iovec aiofn_iovec;

    Py_ssize_t aiofn_writev_sys(int fd, aiofn_iovec* iov, int iovcnt)
    {
        return writev(fd, iov, iovcnt);
    }
#endif
    #define AIOFN_MAX_IOVEC 256

    PyObject* aiofn_allocate_bytes(Py_ssize_t sz, char** ptr)
    {
        PyObject* obj = PyBytes_FromStringAndSize(NULL, sz);
        if (obj == NULL)
        {
            *ptr = NULL;
            PyErr_SetString(PyExc_MemoryError, "cannot allocate bytes object");
        }
        else
        {
            *ptr = PyBytes_AS_STRING(obj);
        }
        return obj;
    }

    PyObject* aiofn_finalize_bytes(PyObject* obj, Py_ssize_t new_size)
    {
        if (new_size == 0)
        {
            Py_DECREF(obj);
            Py_RETURN_NONE;
        }
        _PyBytes_Resize(&obj, new_size);
        return obj;
    }
    """

    cdef bint AIOFN_IS_APPLE
    cdef bint AIOFN_IS_LINUX
    cdef bint AIOFN_IS_WINDOWS
    cdef int AIOFN_EWOULDBLOCK
    cdef int AIOFN_EAGAIN
    cdef int AIOFN_MAX_IOVEC

    int aiofn_get_last_error()
    void aiofn_set_exc_from_error(int error)
    PyObject* aiofn_allocate_bytes(Py_ssize_t sz, char** buf) except NULL
    bytes aiofn_finalize_bytes(PyObject* obj, Py_ssize_t sz)

    ssize_t recv(int sockfd, void* buf, size_t len, int flags)
    ssize_t send(int sockfd, const void* buf, size_t len, int flags)

    ctypedef struct aiofn_iovec:
        void* iov_base
        size_t iov_len

    ssize_t aiofn_writev_sys(int fd, aiofn_iovec *iov, int iovcnt)


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


cdef inline bytes aiofn_shrink_bytes(PyObject* obj, Py_ssize_t new_size):
    _PyBytes_Resize(&obj, new_size)
    cdef bytes maybe_new_object = <bytes>obj
    # Py_DECREF(maybe_new_object)
    return maybe_new_object


cdef inline object aiofn_maybe_copy_buffer(object buffer):
    if buffer is None:
        raise ValueError("cannot copy None buffer")

    if PyBytes_CheckExact(buffer):
        return buffer

    return bytes(buffer)


cdef inline object aiofn_maybe_copy_buffer_tail(object buffer, char* ptr, Py_ssize_t sz):
    if buffer is None:
        return PyBytes_FromStringAndSize(ptr, sz)

    # Do not copy bytes content, it is safe to make a memory view
    if PyBytes_CheckExact(buffer):
        return memoryview(buffer)[PyBytes_GET_SIZE(buffer) - sz:]

    # Always copy bytearray, bytearray may be used as a permanent write buffer
    # in the upper level protocol.
    if PyByteArray_CheckExact(buffer):
        return PyBytes_FromStringAndSize(ptr, sz)

    # For memoryview we check if it is made from bytes object.
    # In such case it is safe to create another memoryview
    cdef Py_buffer pybuf
    PyObject_GetBuffer(buffer, &pybuf, PyBUF_SIMPLE)
    cdef:
        bint is_bytes = (<PyObject*>pybuf.obj != NULL) and PyBytes_CheckExact(pybuf.obj)
        Py_ssize_t buffer_size = pybuf.len
    PyBuffer_Release(&pybuf)

    if is_bytes:
        return memoryview(buffer)[buffer_size - sz:]
    else:
        return PyBytes_FromStringAndSize(ptr, sz)