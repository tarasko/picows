cdef class Transport:
    cpdef write(self, buffer)
    cdef write_mem(self, char* ptr, Py_ssize_t sz)