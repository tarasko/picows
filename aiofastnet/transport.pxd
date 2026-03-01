cdef class Transport:
    cpdef write(self, buffer)
    cdef write_mem(self, char* ptr, Py_ssize_t sz)


cdef class Protocol:
    cpdef is_buffered_protocol(self)
    cpdef get_buffer(self, Py_ssize_t hint)
    cpdef buffer_updated(self, Py_ssize_t bytes_read)
    cpdef data_received(self, data)
    cpdef get_local_write_buffer_size(self)


cpdef is_buffered_protocol(object)
cdef call_get_buffer(protocol, Py_ssize_t hint)
cdef call_buffer_updated(protocol, Py_ssize_t bytes_read)
cdef call_data_received(protocol, data)
