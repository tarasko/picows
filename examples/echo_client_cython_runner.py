import asyncio
import uvloop

from .echo_client_cython import main


if __name__ == '__main__':
    uvloop.install()
    asyncio.run(main("ws://127.0.0.1:9001", 100000))
