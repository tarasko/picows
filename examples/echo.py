import asyncio
from logging import getLogger, DEBUG, INFO, basicConfig
from picows import WSFrame, WSTransport, ws_create_server, WSListener, ws_connect, WSMsgType
from time import time

_logger = getLogger(__name__)


class ServerListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        self._transport = transport

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        self._transport.send(frame.opcode, frame.get_payload_as_bytes())


class ClientListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        self._transport = transport
        self._transport.send(WSMsgType.BINARY, b"Hello world")
        self._last_send_ts = time()

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        ts = time()
        _logger.info("%s: rtt %.3f", frame.get_payload_as_ascii_text(), 1e3 * (ts - self._last_send_ts))
        self._transport.send(WSMsgType.BINARY, frame.get_payload_as_bytes())
        self._last_send_ts = ts


async def async_main():
    server = await ws_create_server("ws://127.0.0.1:9001", ServerListener, "server")
    server_task = asyncio.get_running_loop().create_task(server.serve_forever())
    await asyncio.sleep(1)
    (_, client) = await ws_connect("ws://127.0.0.1:9001", ClientListener, "client")
    await asyncio.sleep(10)


if __name__ == '__main__':
    basicConfig(level=INFO)
    asyncio.run(async_main())
