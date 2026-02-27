import asyncio
import logging
import ssl

from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode


_logger = logging.getLogger("echo_client")


class ClientListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        transport.send(WSMsgType.TEXT, b"Hello world")

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        _logger.info(f"Echo reply: {frame.get_payload_as_ascii_text()}")
        transport.send_close(WSCloseCode.OK)
        transport.disconnect()


async def main(url):
    asyncio.get_running_loop().set_debug(True)
    transport, client = await ws_connect(ClientListener, url)
    await transport.wait_disconnected()


if __name__ == '__main__':
    logging.basicConfig(level=9)
    asyncio.run(main("ws://127.0.0.1:9001"))
