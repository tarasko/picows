import asyncio
import os
import pathlib
import ssl
from logging import getLogger, INFO, basicConfig
from ssl import SSLContext

from picows import WSFrame, WSTransport, ws_create_server, WSListener, WSMsgType

_logger = getLogger(__name__)


class PicowsServerListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        self._transport = transport

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        self._transport.send(frame.msg_type, frame.get_payload_as_bytes())
        if frame.msg_type == WSMsgType.CLOSE:
            self._transport.disconnect()


async def async_main():
    url = "wss://127.0.0.1:9001"
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(pathlib.Path(__file__).parent.parent / "tests" / "picows_test.crt",
                                pathlib.Path(__file__).parent.parent / "tests" / "picows_test.key")
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    server = await ws_create_server(url, PicowsServerListener, "server", ssl_context=ssl_context)
    _logger.info("Server started on %s", url)
    server_task = asyncio.get_running_loop().create_task(server.serve_forever())
    await server_task


if __name__ == '__main__':
    if os.name != 'nt':
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        
    basicConfig(level=INFO)
    asyncio.run(async_main())
