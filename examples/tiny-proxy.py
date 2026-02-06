import asyncio
import anyio

from tiny_proxy import Socks5ProxyHandler
from tiny_proxy import Socks4ProxyHandler
from tiny_proxy import HttpProxyHandler


async def sock4_proxy():
    handler = Socks4ProxyHandler(username='user')
    listener = await anyio.create_tcp_listener(local_host='127.0.0.1', local_port=10400)
    await listener.serve(handler.handle)


async def sock5_proxy():
    handler = Socks5ProxyHandler(username='user', password='password')
    listener = await anyio.create_tcp_listener(local_host='127.0.0.1', local_port=10500)
    await listener.serve(handler.handle)


async def http_proxy():
    handler = HttpProxyHandler(username='user', password='password')
    listener = await anyio.create_tcp_listener(local_host='127.0.0.1', local_port=10100)
    await listener.serve(handler.handle)


async def async_main():
    await asyncio.gather(
        sock4_proxy(),
        sock5_proxy(),
        http_proxy(),
    )

if __name__ == '__main__':
    anyio.run(async_main)

