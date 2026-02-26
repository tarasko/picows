import asyncio
import ssl
from logging import getLogger, basicConfig

from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode


_logger = getLogger("playground")


def create_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


def create_strict_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = True
    ssl_context.hostname_checks_common_name = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    return ssl_context


class ClientListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        ut = transport.underlying_transport
        ssl_object = ut.get_extra_info("ssl_object")
        peercert = ut.get_extra_info("peercert")
        cipher = ut.get_extra_info("cipher")
        compression = ut.get_extra_info("compression")
        transport.send(WSMsgType.TEXT, b"Hello world")

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if b"Request served" in frame.get_payload_as_bytes():
            return

        _logger.info(f"Echo reply: {frame.get_payload_as_ascii_text()}")
        transport.send_close(WSCloseCode.OK)
        transport.disconnect()


async def main(url):
    asyncio.get_event_loop().set_debug(True)
    transport, client = await ws_connect(ClientListener, url, ssl_context=create_strict_client_ssl_context())
    await transport.wait_disconnected()


if __name__ == '__main__':
    basicConfig(level=9)
    asyncio.run(main("wss://echo.websocket.org"))
#    asyncio.run(main("wss://127.0.0.1:9002"))
