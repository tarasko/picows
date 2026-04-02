import asyncio
from threading import current_thread, Event, Thread
from time import time

from picows import (ws_connect, WSFrame, WSTransport, WSListener, WSMsgType,
                    WSCloseCode)


class ClientListener(WSListener):
    request_cnt: int
    start_ts: float

    def __init__(self):
        self.request_cnt = 0
        self.start_ts = time()

    def on_ws_connected(self, transport: WSTransport):
        self.start_ts = time()
        self._send(transport)

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if frame.msg_type == WSMsgType.CLOSE:
            transport.send_close(WSCloseCode.OK)
            transport.disconnect()
        else:
            self._send(transport)

    def _send(self, transport):
        transport.send(WSMsgType.TEXT, b"Hello world")
        self.request_cnt += 1


class ClientThread(Thread):
    url: str
    stop_event: Event

    def __init__(self, url, index, stop_event: Event):
        super().__init__(name=f"echo-client-{index}",)
        self.url = url
        self.stop_event = stop_event

    def run(self):
        try:
            asyncio.run(self.run_async())
        except BaseException as exc:
            print(f"{current_thread().name}: exception raised by server thread: {exc}")
        finally:
            self.stop_event.set()

    async def run_async(self):
        transport, client = await ws_connect(ClientListener, self.url)

        await asyncio.to_thread(self.stop_event.wait)
        transport.disconnect()
        await transport.wait_disconnected()
        rps = client.request_cnt / (time() - client.start_ts)
        print(f"{current_thread().name}: {rps=}")


def main(url):
    num_threads = 2
    stop_event = Event()
    threads = [ClientThread(url, index, stop_event)
               for index in range(num_threads)]

    for thread in threads:
        thread.start()

    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        stop_event.set()
        for thread in threads:
            thread.join()


if __name__ == '__main__':
    main("ws://127.0.0.1:9001")
