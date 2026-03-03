from cpython.object cimport (
    PyObject
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
    void aiofn_set_exc_from_error(int err) {
        (void)err;
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

