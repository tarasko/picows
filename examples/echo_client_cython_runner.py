import asyncio
import ssl

import uvloop

from .echo_client_cython import main

def create_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context

if __name__ == '__main__':
    uvloop.install()
    ssl_context = create_client_ssl_context()
    asyncio.run(main("wss://127.0.0.1:9002", 256, ssl_context))
