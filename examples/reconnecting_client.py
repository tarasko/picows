import asyncio
from logging import getLogger, INFO, basicConfig

from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType

_logger = getLogger(__name__)


class ClientListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        transport.send(WSMsgType.TEXT, b"Hello world")

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if frame.msg_type == WSMsgType.TEXT:
            _logger.info("Echo reply: %s", frame.get_payload_as_ascii_text())

            # Throw from on_ws_frame to illustrate how library deal with exceptions
            # picows will disconnect client and re-raise exception from wait_disconnected
            raise RuntimeError("some logic failed")


async def main(url):
    while True:
        try:
            transport, client = await ws_connect(ClientListener, url)
            await transport.wait_disconnected()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            _logger.error("Client disconnected, reconnect in 5 seconds: %s", str(e))
            await asyncio.sleep(5)


if __name__ == '__main__':
    basicConfig(level=INFO)
    asyncio.run(main("ws://127.0.0.1:9001"))
