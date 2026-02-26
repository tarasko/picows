import asyncio
import logging
import ssl

from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode


def create_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


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
    transport, client = await ws_connect(ClientListener, url, ssl_context=create_client_ssl_context())
    await transport.wait_disconnected()


if __name__ == '__main__':
    logging.basicConfig(level=9)
    asyncio.run(main("wss://echo.websocket.org"))
