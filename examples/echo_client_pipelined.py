import asyncio
import struct
import time
from statistics import mean, median, stdev

from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode


class ClientListener(WSListener):
    def __init__(self, window_size, num_messages, message_len):
        self._transport = None
        self._window_size = window_size
        self._num_messages = num_messages
        # Reserve 4 bytes in the beginning for msg_id
        self._message = bytearray(b"a") * (message_len + 4)
        self._message_mv = memoryview(self._message)
        self._received_cnt = 0
        self._sent_cnt = 0

        self.client_send_times = {}
        self.rtt_times = {}

    def on_ws_connected(self, transport: WSTransport):
        self._transport = transport
        self._fill_send_window()

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if frame.msg_type == WSMsgType.CLOSE:
            self._graceful_disconnect(frame.get_close_code())
            return

        self._received_cnt += 1

        # Get last 4 bytes, don't copy payload, interpret them as int
        msg_id = struct.unpack("=I", frame.get_payload_as_memoryview()[:4])[0]
        self.rtt_times[msg_id] = time.perf_counter() - self.client_send_times[msg_id]
        if self._received_cnt == self._num_messages:
            self._graceful_disconnect(WSCloseCode.OK)
            return

        self._fill_send_window()

    def _fill_send_window(self):
        while self._sent_cnt < self._num_messages and self._sent_cnt - self._received_cnt < self._window_size:
            self._message_mv[:4] = struct.pack("=I", self._sent_cnt)
            self.client_send_times[self._sent_cnt] = time.perf_counter()
            self._transport.send(WSMsgType.BINARY, self._message)
            self._sent_cnt += 1

    def _graceful_disconnect(self, close_code: WSCloseCode):
        self._transport.send_close(close_code)
        self._transport.disconnect()


async def main():
    transport: WSTransport
    client: ClientListener

    def client_factory():
        return ClientListener(window_size=100, num_messages=1000,
                              message_len=64 * 1024)

    transport, client = await ws_connect(client_factory, "ws://127.0.0.1:9001")
    await transport.wait_disconnected()
    times_ms = list(1e3 * t for t in client.rtt_times.values())
    print(f"rtt: mean={mean(times_ms):.3f}ms, median={median(times_ms):.3f}ms, stddev={stdev(times_ms):.3f}ms")


if __name__ == '__main__':
    asyncio.run(main())
