import asyncio
import multiprocessing
import time

from picows import ws_connect, ws_create_server, WSFrame, WSListener, WSMsgType, WSTransport

HOST = "127.0.0.1"
PORT = 9001


class ServerClientListener(WSListener):
    def __init__(self):
        self.transport = None
        self._push_task = None
        self._is_paused = False
        self._counter = 0

    def on_ws_connected(self, transport: WSTransport):
        self.transport = transport

        # Keep small watermarks so pause/resume can be observed quickly.
        self.transport.underlying_transport.set_write_buffer_limits(high=32 * 1024, low=16 * 1024)

        self._push_task = asyncio.get_running_loop().create_task(self._push_forever())

    async def _push_forever(self):
        while True:
            if self._is_paused:
                await asyncio.sleep(0.001)
                continue

            self.transport.send(WSMsgType.TEXT, f"tick-{self._counter}".encode("ascii"))
            self._counter += 1
            await asyncio.sleep(0)

    def pause_writing(self):
        self._is_paused = True
        print("[server] pause_writing")

    def resume_writing(self):
        self._is_paused = False
        print("[server] resume_writing")

    def on_ws_disconnected(self, transport: WSTransport):
        if self._push_task is not None:
            self._push_task.cancel()


class SlowClientListener(WSListener):
    def __init__(self):
        self._received = 0

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if frame.msg_type != WSMsgType.TEXT:
            return

        # Emulate expensive CPU-bound work in the event loop thread.
        time.sleep(0.01)

        self._received += 1
        if self._received % 100 == 0:
            print(f"[client] received={self._received}")


async def run_client(url: str):
    transport, _ = await ws_connect(SlowClientListener, url)
    await transport.wait_disconnected()


def run_client_process(url: str):
    asyncio.run(run_client(url))


async def main():
    server = await ws_create_server(lambda _: ServerClientListener(), HOST, PORT)
    print(f"Server started at ws://{HOST}:{PORT}")

    client_process = multiprocessing.Process(target=run_client_process, args=(f"ws://{HOST}:{PORT}",), daemon=True)
    client_process.start()

    try:
        await asyncio.sleep(5)
    finally:
        client_process.terminate()
        client_process.join(timeout=1)
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
