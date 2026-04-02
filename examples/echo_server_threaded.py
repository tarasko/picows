import asyncio
from threading import current_thread, Thread, Event

from picows import ws_create_server, WSFrame, WSTransport, WSListener, \
    WSMsgType, WSUpgradeRequest


class ServerClientListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        print(f"{current_thread().name}: new client connected")

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if frame.msg_type == WSMsgType.CLOSE:
            transport.send_close(frame.get_close_code(), frame.get_close_message())
            transport.disconnect()
        else:
            transport.send(frame.msg_type, frame.get_payload_as_bytes(), frame.fin, frame.rsv1)


class ServerThread(Thread):
    def __init__(self, index, stop_event: Event):
        super().__init__(name=f"echo-server-{index}")
        self.stop_event = stop_event

    async def run_async(self):
        def listener_factory(r: WSUpgradeRequest):
            # Routing can be implemented here by analyzing request content
            return ServerClientListener()

        server: asyncio.Server = await ws_create_server(listener_factory,
                                                        "127.0.0.1", 9001,
                                                        reuse_port=True)
        for s in server.sockets:
            print(f"{current_thread().name}: server started on {s.getsockname()}")

        await asyncio.to_thread(self.stop_event.wait)
        print(
            f"{current_thread().name}: close event received, disconnect clients and stop server")

        server.close_clients()
        server.close()
        await server.wait_closed()

    def run(self):
        try:
            asyncio.run(self.run_async())
        except BaseException as exc:
            print(f"{current_thread().name}: exception raised by server thread: {exc}")
        finally:
            self.stop_event.set()


def main():
    num_threads = 2
    stop_event = Event()
    threads = [ServerThread(index, stop_event) for index in range(num_threads)]

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
    main()
