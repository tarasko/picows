from .system cimport *

cdef aiofn_unpack_buffer(object bytes_like_obj, char** ptr_out, Py_ssize_t* size_out)
cdef bytes aiofn_shrink_bytes(PyObject* obj, Py_ssize_t new_size)
cdef object aiofn_maybe_copy_buffer(object buffer)
cdef object aiofn_maybe_copy_buffer_tail(object buffer, char* ptr, Py_ssize_t sz)
cdef Py_ssize_t aiofn_recv(int sockfd, void* buf, Py_ssize_t len) except? -1
cdef Py_ssize_t aiofn_send(int sockfd, void* buf, Py_ssize_t len) except? -1
cdef Py_ssize_t aiofn_writev(int sockfd, aiofn_iovec* iov, Py_ssize_t iovcnt) except? -1
