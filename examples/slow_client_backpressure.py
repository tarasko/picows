# This example demonstrates how to deal with slow clients that are not able to
# process data from server.
# By overriding WSListener.pause_writing, WSListener.stop_writing server
# can handle backpressure and implement the most appropriate strategy.

# This example starts:
# a WebSocket server that continuously pushes incrementing counters,
# a client in another process (using multiprocessing),
# and a deliberately slow client handler that blocks its event loop with time.sleep(0.01) for every incoming frame.

import asyncio
import logging
import multiprocessing
import random
import time
from logging import basicConfig

from picows import ws_connect, ws_create_server, WSFrame, WSListener, WSMsgType, WSTransport

HOST = "127.0.0.1"
PORT = 9001


class ServerClientListener(WSListener):
    def __init__(self):
        self._push_task = None
        self._write_resumed_fut = None
        self._counter = 0

    def on_ws_connected(self, transport: WSTransport):
        # Keep small watermarks so pause/resume can be observed quickly.
        transport.underlying_transport.set_write_buffer_limits(high=32 * 1024, low=16 * 1024)
        self._push_task = asyncio.get_running_loop().create_task(self._push_forever(transport))

    async def _push_forever(self, transport: WSTransport):
        # Send message of 1024 bytes
        msg = random.randbytes(1024)
        while True:
            # If writing is paused then waiting until it is un-paused
            if self._write_resumed_fut is not None:
                await self._write_resumed_fut

            transport.send(WSMsgType.BINARY, msg)
            self._counter += 1
            if self._counter % 1000 == 0:
                print(f"[server] push_forever, counter={self._counter}")

    def pause_writing(self):
        self._write_resumed_fut = asyncio.get_running_loop().create_future()
        print(f"[server] pause_writing, sent {self._counter}")

    def resume_writing(self):
        self._write_resumed_fut.set_result(None)
        self._write_resumed_fut = None
        print("[server] resume_writing")

    def on_ws_disconnected(self, transport: WSTransport):
        if self._push_task is not None:
            self._push_task.cancel()


class SlowClientListener(WSListener):
    def __init__(self):
        self._received = 0

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        # Emulate expensive CPU-bound work in the event loop thread.
        time.sleep(0.01)

        self._received += 1
        if self._received % 100 == 0:
            # WSFrame(..., tail_sz=?) indicates how much data is still in the
            # read buffer that has NOT been delivered to on_ws_frame yet.
            # last_in_buffer=False, indicates that we already have next complete
            # frame and on_ws_frame will be called right after current on_ws_frame
            # is complete.
            print(f"[client] received={self._received}, {frame}")


def run_client_process(url: str):
    async def run_client(url: str):
        transport, _ = await ws_connect(SlowClientListener, url)
        await transport.wait_disconnected()

    asyncio.run(run_client(url))


async def main():
    server = await ws_create_server(lambda _: ServerClientListener(), HOST, PORT)
    print(f"Server started at ws://{HOST}:{PORT}")

    client_process = multiprocessing.Process(target=run_client_process, args=(f"ws://{HOST}:{PORT}",), daemon=True)
    client_process.start()

    try:
        await asyncio.sleep(20)
    finally:
        client_process.terminate()
        client_process.join(timeout=1)
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    basicConfig(level=logging.ERROR)
    asyncio.run(main())
