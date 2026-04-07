import concurrent
from concurrent.futures.thread import ThreadPoolExecutor

import pytest

import picows
from tests.utils import WSServer, WSClient


class EchoClient(picows.WSListener):
    transport: picows.WSTransport
    _msg: bytes = None
    _done_fut: concurrent.futures.Future[None] = None
    _rounds: int = None

    def on_ws_connected(self, transport: picows.WSTransport):
        self.transport = transport

    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        self._rounds -= 1
        if self._rounds > 0:
            self.transport.send(picows.WSMsgType.BINARY, self._msg)
        else:
            self._done_fut.set_result(None)
            self.transport.disconnect()

    def start_echo_loop(self, msg, rounds, done_fut):
        self._msg = msg
        self._done_fut = done_fut
        self._rounds = rounds
        self.transport.send(picows.WSMsgType.BINARY, self._msg)


@pytest.mark.codspeed
@pytest.mark.parametrize("msg_size", [64, 8192, 64 * 1024])
async def test_bench_echo(msg_size, benchmark):
    # benchmark.pendantic is non-async.
    # But we need it to measure performance of a particular async function
    with ThreadPoolExecutor(max_workers=1) as executor:
        async with WSServer() as server:
            async with WSClient(server, EchoClient) as client:
                msg = b"X" * msg_size

                done_fut = concurrent.futures.Future()
                p_f = executor.submit(benchmark.pedantic, done_fut.result, rounds=1, iterations=1)

                client.start_echo_loop(msg, 10000, done_fut)
                await client.transport.wait_disconnected()

                p_f.result()
