# This example shows how to maintain a set of active clients and broadcast messages to everybody.
# The set contains weak references to clients, it is done in order to prevent client from holding references
# to other clients when server is dead.


import asyncio
import itertools
from typing import Optional
from weakref import ref, ReferenceType

from picows import ws_create_server, WSFrame, WSTransport, WSListener, \
    WSMsgType, WSUpgradeRequest


class ServerClientListener(WSListener):
    def __init__(self, all_clients):
        self.transport = None
        self._all_clients = all_clients

    def on_ws_connected(self, transport: WSTransport):
        self.transport = transport
        self._all_clients.add(ref(self))

    def on_ws_disconnected(self, transport: WSTransport):
        self._all_clients.remove(ref(self))

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        if frame.msg_type == WSMsgType.CLOSE:
            transport.send_close(frame.get_close_code(), frame.get_close_message())
            transport.disconnect()

        # ...
        # Custom protocol logic


class Server:
    _all_clients: set[ReferenceType[ServerClientListener]]
    _asyncio_server: Optional[asyncio.Server]

    def __init__(self):
        self._all_clients = set()
        self._asyncio_server = None

    def broadcast(self, message):
        for client_ref in self._all_clients:
            client = client_ref()
            if client is not None:
                client.transport.send(WSMsgType.TEXT, message)

    async def run(self):
        def listener_factory(r: WSUpgradeRequest):
            return ServerClientListener(self._all_clients)

        self._asyncio_server = await ws_create_server(listener_factory, "127.0.0.1", 9001)
        for s in self._asyncio_server.sockets:
            print(f"Server started on {s.getsockname()}")

        await self._asyncio_server.serve_forever()


async def main():
    server = Server()

    async def broadcast_something_every_second():
        for i in itertools.count():
            await asyncio.sleep(1)
            server.broadcast(b"Hello, this is broadcast number #%d" % (i, ))
            print(f"Broadcasted message #{i}")

    await asyncio.gather(server.run(), broadcast_something_every_second())


if __name__ == '__main__':
    asyncio.run(main())
