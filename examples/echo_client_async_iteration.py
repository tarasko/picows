# This example illustrates how you can emulate async iteration interface similar
# to websockets and aiohttp interfaces.

# This example works against publicly available secure websocket echo server
# at wss://echo.websocket.org

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import List, Optional

from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode


@dataclass
class WSMessage:
    msg_type: WSMsgType
    payload: bytes


class ClientListener(WSListener):
    _msg_queue: asyncio.Queue
    _msg_type: WSMsgType
    _msg_fragments: Optional[List[bytes]]

    transport: Optional[WSTransport]

    def __init__(self):
        self._msg_queue = asyncio.Queue()
        self._msg_type = WSMsgType.TEXT
        self._msg_fragments = None
        self.transport = None

    def on_ws_connected(self, transport):
        self.transport = transport

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if frame.fin:
            if self._msg_fragments is None:
                self._msg_queue.put_nowait(WSMessage(frame.msg_type, frame.get_payload_as_bytes()))
            else:
                self._msg_fragments.append(frame.get_payload_as_bytes())
                self._msg_queue.put_nowait(WSMessage(self._msg_type, b"".join(self._msg_fragments)))
                self._msg_fragments = None
        else:
            if self._msg_fragments is None:
                self._msg_type = frame.msg_type
                self._msg_fragments = [frame.get_payload_as_bytes()]
            else:
                self._msg_fragments.append(frame.get_payload_as_bytes())

    def on_ws_disconnected(self, transport: WSTransport):
        # Push None to indicate the end of the stream
        self._msg_queue.put_nowait(None)

    async def recv(self):
        if self.transport.underlying_transport.is_closing():
            return None

        msg = await self._msg_queue.get()
        self._msg_queue.task_done()
        return msg


@asynccontextmanager
async def connect(url: str):
    client: ClientListener
    _, client = await ws_connect(ClientListener, url)
    try:
        yield client
    finally:
        print("Sending close frame and disconnect gracefully")
        client.transport.send_close(WSCloseCode.OK)
        client.transport.disconnect()
        await client.transport.wait_disconnected()
        print("Disconnected")


async def main(url):
    # As you can see, it is not difficult to emulate websockets/aiohttp async
    # iteration interface, while still having full control over message assembly/disassembly,
    # payload processing and flow control
    async with connect(url) as client:
        client.transport.send(WSMsgType.TEXT, b"Hello world")
        greet_msg = await client.recv()
        print(greet_msg)
        echo_msg = await client.recv()
        print(echo_msg)

        await asyncio.sleep(100)


if __name__ == '__main__':
    asyncio.run(main("wss://echo.websocket.org"))
