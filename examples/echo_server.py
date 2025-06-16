# Simple websocket echo server for both plain and ssl connections.

import asyncio
import os
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

    plain_server = await ws_create_server(listener_factory,
                                          "127.0.0.1", 9001,
                                          websocket_handshake_timeout=0.5)
    _logger.info("Server started on %s", plain_server.sockets[0].getsockname())

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(pathlib.Path(__file__).parent.parent / "tests" / "picows_test.crt",
                                pathlib.Path(__file__).parent.parent / "tests" / "picows_test.key")
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_server = await ws_create_server(listener_factory,
                                        "127.0.0.1", 9002,
                                        ssl=ssl_context,
                                        websocket_handshake_timeout=0.5)
    _logger.info("Server started on %s", ssl_server.sockets[0].getsockname())

    await asyncio.gather(plain_server.serve_forever(), ssl_server.serve_forever())


if __name__ == '__main__':
    if os.name != 'nt':
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    basicConfig(level=INFO)
    asyncio.run(async_main())
