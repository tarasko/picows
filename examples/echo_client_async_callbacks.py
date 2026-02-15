import asyncio
from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode


class ClientListener(WSListener):
    def __init__(self):
        self._loop = asyncio.get_running_loop()

    def on_ws_connected(self, transport: WSTransport):
        self._loop.create_task(self.on_ws_connected_async(transport))

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        self._loop.create_task(self.on_ws_frame_async(transport, frame))

    async def on_ws_connected_async(self, transport: WSTransport):
        transport.send(WSMsgType.TEXT, b"Hello world")

    async def on_ws_frame_async(self, transport: WSTransport, frame: WSFrame):
        # !!! DANGER:
        # frame is essentially just a pointer to the receiving buffer.
        # This pointer is invalidated after original on_ws_frame is complete.
        # Here, we can pass and access frame object from async method only
        # because our tasks are created using eager_task_factory.
        # WSFrame is not guaranteed to point at the valid content after any
        # subsequent await method

        # Here the frame is still valid
        print(f"Echo reply: {frame.get_payload_as_ascii_text()}")

        await asyncio.sleep(0.0)

        # Here the frame object is not valid anymore:
        # frame.get_payload_as_ascii_text()
        # May return junk

        transport.send_close(WSCloseCode.OK)
        transport.disconnect()


async def main(url):
    # Enable eager tasks
    # Eager tasks only available since python 3.13
    asyncio.get_running_loop().set_task_factory(asyncio.eager_task_factory)

    transport, client = await ws_connect(ClientListener, url)
    await transport.wait_disconnected()


if __name__ == '__main__':
    asyncio.run(main("ws://127.0.0.1:9001"))
