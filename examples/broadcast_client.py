# A simple client for broadcast_server.py
# Just dump messages from the server

import asyncio
from picows import ws_connect, WSFrame, WSTransport, WSListener


class ClientListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        print("Client connected")

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        print(f"Received: {frame.get_payload_as_ascii_text()}")


async def main(url):
    transport, client = await ws_connect(ClientListener, url)
    await transport.wait_disconnected()


if __name__ == '__main__':
    asyncio.run(main("ws://127.0.0.1:9001"))
