# This example shows how to use WSTransport.measure_roundtrip_time
# It may be used to check connection latency.

import asyncio
import logging

import picows
from picows import ws_connect, WSTransport, WSListener

EXPECTED_OKX_ROUNDTRIP_TIME = 0.1


class ClientListener(WSListener):
    async def check_okx_roundtrip_time(self, transport: picows.WSTransport):
        rtts = await transport.measure_roundtrip_time(5)
        if min(rtts) < EXPECTED_OKX_ROUNDTRIP_TIME:
            print(f"Minimal rtt {min(rtts):.3f} satisfies required {EXPECTED_OKX_ROUNDTRIP_TIME:.3f}")
        else:
            print(f"Minimal rtt {min(rtts):.3f} DOES NOT satisfies required {EXPECTED_OKX_ROUNDTRIP_TIME:.3f}, disconnect",
                  min(rtts), EXPECTED_OKX_ROUNDTRIP_TIME)
            transport.disconnect()

    def send_user_specific_ping(self, transport: picows.WSTransport):
        transport.send(picows.WSMsgType.TEXT, b"ping")

    def is_user_specific_pong(self, frame: picows.WSFrame):
        return frame.msg_type == picows.WSMsgType.TEXT and frame.get_payload_as_memoryview() == b"pong"

    def on_ws_connected(self, transport: WSTransport):
        asyncio.get_running_loop().create_task(self.check_okx_roundtrip_time(transport))


async def main(url):
    while True:
        (transport, client) = await ws_connect(ClientListener, url)
        await transport.wait_disconnected()
        await asyncio.sleep(5)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("picows").setLevel(9)
    asyncio.run(main("wss://ws.okx.com:8443/ws/v5/public"))
