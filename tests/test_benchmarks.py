import asyncio
import pytest

import picows
from tests.utils import WSServer, WSClient


class EchoClient(picows.WSListener):
    transport: picows.WSTransport
    _msg: bytes = None
    _rounds: int = None

    def on_ws_connected(self, transport: picows.WSTransport):
        self.transport = transport

    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        self._rounds -= 1
        if self._rounds > 0:
            self.transport.send(picows.WSMsgType.BINARY, self._msg)
        else:
            self.transport.disconnect()

    def start_echo_loop(self, msg, rounds):
        self._msg = msg
        self._rounds = rounds
        self.transport.send(picows.WSMsgType.BINARY, self._msg)


@pytest.mark.codspeed
@pytest.mark.parametrize("msg_size", [64, 8192, 32 * 1024])
def test_bench_echo(msg_size, benchmark):
    msg = b"X" * msg_size

    async def run():
        async with WSServer() as server:
            async with WSClient(server, EchoClient) as client:
                client.start_echo_loop(msg, 10000)
                await client.transport.wait_disconnected()

    benchmark.pedantic(lambda: asyncio.run(run()), rounds=1, iterations=1)
