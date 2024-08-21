import asyncio
import uvloop
from picows import WSFrame, WSTransport, WSListener, ws_create_server, WSMsgType, WSUpgradeRequest


class ServerClientListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        print("New client connected")

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        transport.send(frame.msg_type, frame.get_payload_as_bytes())
        if frame.msg_type == WSMsgType.CLOSE:
            transport.disconnect()


async def main():
    def listener_factory(r: WSUpgradeRequest):
        # Routing can be implemented here by analyzing request content
        return ServerClientListener()

    server: asyncio.Server = await ws_create_server(listener_factory, "127.0.0.1", 9001)
    for s in server.sockets:
        print(f"Server started on {s.getsockname()}")

    await server.serve_forever()

if __name__ == '__main__':
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    asyncio.run(main())