# Simple websocket echo server for both plain and ssl connections.

import asyncio
import pathlib
import ssl
from logging import getLogger, INFO, basicConfig

from picows import WSFrame, WSTransport, ws_create_server, WSListener, WSMsgType, WSUpgradeRequest

_logger = getLogger(__name__)


class ServerClientListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        self._transport = transport

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        self._transport.send(frame.msg_type, frame.get_payload_as_bytes(), frame.fin, frame.rsv1)
        if frame.msg_type == WSMsgType.CLOSE:
            self._transport.disconnect()


async def async_main():
    def listener_factory(r: WSUpgradeRequest):
        return ServerClientListener()

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(pathlib.Path(__file__).parent.parent / "tests" / "picows_test.crt",
                                pathlib.Path(__file__).parent.parent / "tests" / "picows_test.key")
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_server = await ws_create_server(listener_factory, "127.0.0.1", 9002, ssl=ssl_context)
    _logger.info("Secure server started on %s", ssl_server.sockets[0].getsockname())

    await ssl_server.serve_forever()


if __name__ == '__main__':
    basicConfig(level=INFO)
    asyncio.run(async_main())
