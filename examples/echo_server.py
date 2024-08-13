import asyncio
import os
from logging import getLogger, INFO, basicConfig
from picows import WSFrame, WSTransport, ws_create_server, WSListener, WSMsgType

_logger = getLogger(__name__)


class PicowsServerListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        self._transport = transport

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        self._transport.send(frame.opcode, frame.get_payload_as_bytes())
        if frame.opcode == WSMsgType.CLOSE:
            self._transport.disconnect()


async def async_main():
    url = "ws://127.0.0.1:9001"
    server = await ws_create_server(url, PicowsServerListener, "server")
    _logger.info("Server started on %s", url)
    server_task = asyncio.get_running_loop().create_task(server.serve_forever())
    await server_task


if __name__ == '__main__':
    if os.name != 'nt':
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        
    basicConfig(level=INFO)
    asyncio.run(async_main())
