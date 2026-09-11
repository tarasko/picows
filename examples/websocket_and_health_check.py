# This example shows how to serve a WebSocket endpoint and an HTTP health check on the same port.

import asyncio
from logging import basicConfig

import picows
from picows import (
    WSFrame,
    WSListener,
    WSMsgType,
    WSTransport,
    WSUpgradeRequest,
    WSUpgradeResponse,
    WSUpgradeResponseWithListener,
    ws_create_server,
)


class EchoListener(WSListener):
    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if frame.msg_type == WSMsgType.CLOSE:
            transport.send_close(frame.get_close_code(), frame.get_close_message())
            transport.disconnect()
            return

        transport.send(
            frame.msg_type,
            frame.get_payload_as_memoryview(),
            frame.fin,
            frame.rsv1,
            frame.rsv2,
            frame.rsv3,
        )


def create_health_check_response() -> WSUpgradeResponseWithListener:
    response = WSUpgradeResponse.create_ok_response(b"I'm healthy")
    return WSUpgradeResponseWithListener(response, None)


def listener_factory(request: WSUpgradeRequest):
    if request.path == b"/health":
        return create_health_check_response()
    if request.path == b"/ws":
        return EchoListener()
    return None


async def main():
    server = await ws_create_server(listener_factory, "127.0.0.1", 9001)
    print("Health check: http://127.0.0.1:9001/health")
    print("WebSocket endpoint: ws://127.0.0.1:9001/ws")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    basicConfig(level=picows.PICOWS_DEBUG_LL)
    asyncio.run(main())
