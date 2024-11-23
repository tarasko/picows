from picows import WSListener, WSTransport, WSFrame, WSMsgType, ws_connect, \
    WSError
import asyncio
import json
import time


class WSClient(WSListener):
    def __init__(self, exchange_id: str = ""):
        self._exchange_id = exchange_id
        self.msg_queue = asyncio.Queue()

    def on_ws_connected(self, transport: WSTransport):
        print(f"Connected to {self._exchange_id} Websocket.")

    def on_ws_disconnected(self, transport: WSTransport):
        print(f"Disconnected from {self._exchange_id} Websocket.")

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if frame.msg_type == WSMsgType.PING:
            transport.send_pong(frame.get_payload_as_bytes())
            return
        try:
            msg = json.loads(frame.get_payload_as_utf8_text())
            self.msg_queue.put_nowait(msg)
        except Exception as e:
            print(frame.get_payload_as_bytes())
            print(f"Error parsing message: {e}")


class BinanceWsManager:
    def __init__(self, url: str):
        self._url = url
        self._ping_idle_timeout = 2
        self._ping_reply_timeout = 1
        self._listener = None
        self._transport = None
        self._tasks = []

    async def _connect(self, reconnect: bool = False):
        if not self._transport and not self._listener or reconnect:
            WSClientFactory = lambda: WSClient("Binance")  # noqa: E731
            self._transport, self._listener = await ws_connect(
                WSClientFactory,
                self._url,
                enable_auto_ping=True,
                auto_ping_idle_timeout=self._ping_idle_timeout,
                auto_ping_reply_timeout=self._ping_reply_timeout,
            )

    async def _handle_connection(self):
        reconnect = False
        while True:
            try:
                await self._connect(reconnect)
                # TODO: when reconnecting, need to resubscribe to the channels
                await self._transport.wait_disconnected()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Connection error: {e}")
            reconnect = True
            await asyncio.sleep(1)

    async def subscribe_book_ticker(self, symbol):
        await self._connect()
        id = int(time.time() * 1000)
        payload = {
            "method": "SUBSCRIBE",
            "params": [f"{symbol.lower()}@bookTicker"],
            "id": id,
        }
        self._transport.send(WSMsgType.TEXT,
                             json.dumps(payload).encode("utf-8"))

    async def subscribe_trade(self, symbol):
        await self._connect()
        id = int(time.time() * 1000)
        payload = {
            "method": "SUBSCRIBE",
            "params": [f"{symbol.lower()}@trade"],
            "id": id,
        }
        self._transport.send(WSMsgType.TEXT,
                             json.dumps(payload).encode("utf-8"))

    async def _msg_handler(self):
        while True:
            msg = await self._listener.msg_queue.get()
            # TODO: handle different event types of messages
            print(msg)
            self._listener.msg_queue.task_done()

    async def start(self):
        asyncio.create_task(self._msg_handler())
        await self._handle_connection()


async def main():
    try:
        url = "wss://stream.binance.com:9443/ws"
        ws_manager = BinanceWsManager(url)
        await ws_manager.subscribe_book_ticker("BTCUSDT")
        await ws_manager.subscribe_book_ticker("ETHUSDT")
        # await ws_manager.subscribe_book_ticker("SOLUSDT")
        # await ws_manager.subscribe_book_ticker("BNBUSDT")
        # await ws_manager.subscribe_trade("BTCUSDT")
        # await ws_manager.subscribe_trade("ETHUSDT")
        # await ws_manager.subscribe_trade("BNBUSDT")
        # await ws_manager.subscribe_trade("SOLUSDT")
        await ws_manager.start()

    except asyncio.CancelledError:
        print("Websocket closed.")


if __name__ == "__main__":
    asyncio.run(main())