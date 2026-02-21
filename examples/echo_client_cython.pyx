# This example shows how you can use Cython and access picows pxd type
# declarations to further improve performance of your code.
from time import time

from picows import ws_connect
from picows.picows cimport WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode

# WSListener is a cython extension type. We can derive it and efficiently
# override its methods like on_ws_frame. This way methods will be called
# directly by picows without using more expensive python vectorcall protocol.
# See echo_client_cython_runner.py for how to connect the client
cdef class ClientListenerCython(WSListener):
    cdef:
        double _start_ts
        bytes _msg
        int _cnt

    def __init__(self, msg_size):
        self._start_ts = time()
        self._msg = b"T" * msg_size
        self._cnt = 0

    cpdef on_ws_connected(self, WSTransport transport):
        transport.send(WSMsgType.TEXT, self._msg)

    cpdef on_ws_frame(self, WSTransport transport, WSFrame frame):
        self._cnt += 1
        if <double>time() - self._start_ts < 10.0:
            transport.send(WSMsgType.TEXT, self._msg)
        else:
            print(f"Total {self._cnt} echo request-replies executed")
            transport.send_close(WSCloseCode.OK)
            transport.disconnect()


