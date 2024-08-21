from logging import getLogger
from libc.errno cimport errno

from picows.picows cimport WSFrame, WSTransport, WSListener, WSMsgType
from picows import ws_connect

_logger = getLogger(__name__)

cdef extern from "<stdlib.h>" nogil:
    enum clockid_t:
        CLOCK_REALTIME
        CLOCK_MONOTONIC
        CLOCK_MONOTONIC_RAW

    cdef struct timespec:
        long tv_sec
        long tv_nsec

    int clock_gettime (clockid_t clock, timespec *ts)


cdef double get_now_timestamp() except -1.0:
    cdef timespec tspec

    if clock_gettime(CLOCK_REALTIME, &tspec) == -1:
        raise RuntimeError("clock_gettime failed: %d", errno)

    return <double>tspec.tv_sec + <double>tspec.tv_nsec * 1e-9


cdef class EchoClientListener(WSListener):
    cdef:
        WSTransport _transport
        double _begin_time
        int _duration
        int _cnt
        bytes _data
        bytearray _full_reply
        readonly int rps

    def __init__(self, bytes data, int duration):
        super().__init__()
        self._transport = None
        self._begin_time = 0
        self._duration = duration
        self._cnt = 0
        self._data = data
        self._full_reply = bytearray()
        self.rps = 0

    cpdef on_ws_connected(self, WSTransport transport):
        self._transport = transport
        self._begin_time = get_now_timestamp()
        self._transport.send(WSMsgType.BINARY, self._data)

    cpdef on_ws_frame(self, WSTransport transport, WSFrame frame):
        if frame.fin:
            if self._full_reply:
                self._full_reply += frame.get_payload_as_memoryview()
                self._full_reply.clear()
        else:
            self._full_reply += frame.get_payload_as_memoryview()
            return

        self._cnt += 1
        cdef double ts = get_now_timestamp()

        if ts - self._begin_time >= self._duration:
            self.rps = int(self._cnt / self._duration)
            self._transport.disconnect()
        else:
            self._transport.send(WSMsgType.BINARY, self._data)


async def picows_main_cython(url: str, data: bytes, duration: int, ssl_context):
    cdef EchoClientListener client
    (_, client) = await ws_connect(lambda: EchoClientListener(data, duration),
                                   url,
                                   ssl_context=ssl_context)
    await client._transport.wait_disconnected()
    return client.rps
