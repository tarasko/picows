# This example shows how you can send fragmented websocket message (
# consisting of multiple frames) and assemble message back from multiple frames

import asyncio
from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode


class ClientListener(WSListener):
    _msg_type: WSMsgType
    _msg: bytearray

    def __init__(self):
        self._msg_type = None
        self._msg = bytearray()

    def on_ws_connected(self, transport: WSTransport):
        # Let's send a fragmented message and assemble it back in on_ws_frame

        # The first frame of fragmented message defines message type.
        transport.send(WSMsgType.TEXT, b"Hello ", fin=False)
        # All subsequent frames have WSMsgType.CONTINUATION type
        transport.send(WSMsgType.CONTINUATION, b"world", fin=False)
        # Final frame has fin=True
        transport.send(WSMsgType.CONTINUATION, b"!!!", fin=True)

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        # picows doesn't assemble fragmented messages from frames.
        # User is supposed to do it using the most suitable strategy.
        # Here we just accumulate payload in bytearray until fin=True frame
        # is arrived.

        if frame.msg_type != WSMsgType.CONTINUATION:
            self._msg_type = frame.msg_type

        self._msg += frame.get_payload_as_memoryview()

        if frame.fin:
            print(f"Full {self._msg_type.name} message has arrived: {self._msg}")
            transport.send_close(WSCloseCode.OK)
            transport.disconnect()


async def main(url):
    transport, client = await ws_connect(ClientListener, url)
    await transport.wait_disconnected()


if __name__ == '__main__':
    asyncio.run(main("ws://127.0.0.1:9001"))
