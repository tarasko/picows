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

