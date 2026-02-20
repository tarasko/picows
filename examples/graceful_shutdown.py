import asyncio
from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode


class ClientListener(WSListener):

    def on_ws_connected(self, transport: WSTransport):
        transport.send(WSMsgType.TEXT, b"Hello world")

    def _initiate_graceful_shutdown(self, transport: WSTransport):
        # It is absolutely fine to call send_close or disconnect multiple times.
        # Any subsequent send operation is no-op after send_close is called.
        # send_close itself doesn't initiate disconnect. It is just close websocket
        # for writing. Technically the peer may still keep sending more data for a while.
        transport.send_close(WSCloseCode.OK, b"done")

        # This is what actually tells asyncio to close the socket.
        # By default, asyncio does a graceful close.
        # Asyncio will attempt to send remaining data in the
        # write buffer before actually closing the socket. So CLOSE frame is guaranteed
        # to be delivered to the peer. There is no race between send_close and disconnect.

        # This may have an unexpected side effect that on_ws_disconnected will be called much
        # later, after all write buffers are flushed.

        # If you want to close socket immediately without flushing buffered data
        # call transport.disconnect(graceful=False)
        transport.disconnect()

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if frame.msg_type == WSMsgType.CLOSE:
            # In case when peer initiated close: echo CLOSE and disconnect.
            # But it was a reply to our own CLOSE then picows will ignore send_close
            # since transport.is_close_frame_sent == True.
            print(f"Close frame received: {frame.get_close_code()}, {frame.get_close_message()}")
            transport.send_close(frame.get_close_code(), frame.get_close_message())
            transport.disconnect()
            return

        print(f"Echo reply: {frame.get_payload_as_ascii_text()}")
        # We initiated close: send CLOSE first, then disconnect.
        self._initiate_graceful_shutdown(transport)

    def on_ws_disconnected(self, transport):
        print("Socket disconnected")


async def main(url):
    transport, _ = await ws_connect(ClientListener, url)
    await transport.wait_disconnected()


if __name__ == '__main__':
    asyncio.run(main("ws://127.0.0.1:9001"))
