import asyncio
import os
import ssl
from logging import getLogger, basicConfig

import async_timeout
import uvloop

from tests.utils import AsyncClient

from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode


_logger = getLogger("playground")


def create_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


def create_strict_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = True
    ssl_context.hostname_checks_common_name = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    return ssl_context


class ClientListenerSimple(WSListener):
    def on_ws_connected(self, transport: WSTransport):
        ut = transport.underlying_transport
        ssl_object = ut.get_extra_info("ssl_object")
        peercert = ut.get_extra_info("peercert")
        cipher = ut.get_extra_info("cipher")
        compression = ut.get_extra_info("compression")
        # transport.send(WSMsgType.TEXT, b"Hello world")
        transport.send(WSMsgType.TEXT, b"b"*1024*256)

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if b"Request served" in frame.get_payload_as_bytes():
            return

        # _logger.info(f"Echo reply: {frame.get_payload_as_ascii_text()}")
        transport.send_close(WSCloseCode.OK)
        transport.disconnect()


async def main(url):
    asyncio.get_event_loop().set_debug(True)
    try:
        transport, client = await ws_connect(AsyncClient, url, ssl_context=create_client_ssl_context())
        # client.transport.underlying_transport.set_write_buffer_limits(256, 128)
        msg1 = b"a"*307
        msg2 = b"b"*311
        msg3 = b"c"*313

        total_batches = 0
        while not client.is_paused:
            client.transport.send(WSMsgType.BINARY, msg1)
            client.transport.send(WSMsgType.BINARY, msg2)
            client.transport.send(WSMsgType.BINARY, msg3)
            total_batches += 1

        # Add extra batch to make sure we utilize loop buffers above high watermark
        client.transport.send(WSMsgType.BINARY, msg1)
        client.transport.send(WSMsgType.BINARY, msg2)
        client.transport.send(WSMsgType.BINARY, msg3)
        total_batches += 1

        # await asyncio.sleep(1)

        _logger.info(f"Total messages sent: {total_batches*3}")

        for i in range(total_batches * 3):
#            async with async_timeout.timeout(0.5):
            frame = await client.get_message_no_timeout()
            if i % 3 == 0:
                assert frame.payload_as_bytes == msg1
            elif i % 3 == 1:
                assert frame.payload_as_bytes == msg2
            else:
                assert frame.payload_as_bytes == msg3
            if i % 10 == 0:
                _logger.info(f"Message #{i} received")

        _logger.info("Successfully read all batches")
        transport.disconnect()
        await transport.wait_disconnected()
    except Exception as exc:
        print(exc)


if __name__ == '__main__':
    basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=9)
#     asyncio.run(main("wss://echo.websocket.org"))
    asyncio.run(main("ws://127.0.0.1:9001"))
