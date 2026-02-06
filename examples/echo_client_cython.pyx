# This example shows how you can use Cython and access picows pxd type
# declarations to further improve performance of your code.

from picows.picows cimport WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode
from picows import ws_connect

import asyncio

# WSListener is a cython extension type. We can derive it and efficiently
# override its methods like on_ws_frame. This way methods will be called
# directly by picows without using more expensive python vectorcall protocol.
cdef class ClientListener(WSListener):
    cpdef on_ws_connected(self, WSTransport transport):
        self._transport.send(WSMsgType.TEXT, b"Hello world")

    cpdef on_ws_frame(self, WSTransport transport, WSFrame frame):
        print(f"Echo reply: {frame.get_payload_as_ascii_text()}")
        transport.send_close(WSCloseCode.OK)
        transport.disconnect()


async def main(url):
    transport, client = await ws_connect(ClientListener, url)
    await transport.wait_disconnected()


if __name__ == '__main__':
    asyncio.run(main("ws://127.0.0.1:9001"))
