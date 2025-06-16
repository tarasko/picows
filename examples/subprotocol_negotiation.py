# This example shows how to implement subprotocol negotiation at upgrade stage.
# In websockets this is done by sending "Sec-WebSocket-Protocol" header in HTTP Upgrade request/response.
# picows treats "Sec-WebSocket-Protocol" as any other extra header and let user to fully define it's content both
# at client and server sides.

import asyncio
import logging
from http import HTTPStatus
from picows import ws_connect, WSTransport, WSListener, \
    ws_create_server, WSUpgradeResponse, WSUpgradeResponseWithListener, \
    WSUpgradeRequest


class OCPPServerClientListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        print("New client connected, negotiated protocol: ", transport.response.headers["Sec-WebSocket-Protocol"])


class OCPPClientListener(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        print("Successfully connected to the server, server supports: ",
              transport.response.headers["Sec-WebSocket-Protocol"])


async def main():
    def server_client_factory(request: WSUpgradeRequest):
        if "ocpp2.1" in request.headers["Sec-WebSocket-Protocol"]:
            return WSUpgradeResponseWithListener(
                WSUpgradeResponse.create_101_response(extra_headers={"Sec-WebSocket-Protocol": "ocpp2.1"}),
                OCPPServerClientListener())
        else:
            return WSUpgradeResponseWithListener(
                WSUpgradeResponse.create_error_response(
                    HTTPStatus.BAD_REQUEST,
                    b"requested websocket subprotocol is not supported"
                ),
                None)

    server = await ws_create_server(server_client_factory, "127.0.0.1", 27001)
    asyncio.create_task(server.serve_forever())

    # Client request support for either ocpp1.6 or ocpp2.1 protocol
    (transport, client) = await ws_connect(
        OCPPClientListener,
        "ws://127.0.0.1:27001/",
        extra_headers={"Sec-WebSocket-Protocol": "ocpp1.6,ocpp2.1"}
    )

    transport.disconnect()
    await transport.wait_disconnected()

    server.close()
    await server.wait_closed()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("picows").setLevel(9)
    asyncio.run(main())
