# This example shows how to use cythonize implementation of WSListener interface
# See echo_client_cython.pyx

import asyncio
import ssl

from picows import ws_connect
from examples.echo_client_cython import ClientListenerCython

USE_TLS = False

def create_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


async def main(url, msg_size, duration, ssl_context):
    transport, client = await ws_connect(
        lambda: ClientListenerCython(msg_size, duration),
        url,
        ssl_context=ssl_context)
    await transport.wait_disconnected()


if __name__ == '__main__':
    if USE_TLS:
        ssl_context = create_client_ssl_context()
        asyncio.run(main("wss://127.0.0.1:9002", 256, 5, ssl_context))
    else:
        asyncio.run(main("ws://127.0.0.1:9001", 256, 5, None))
