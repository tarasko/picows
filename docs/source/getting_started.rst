Getting started
===============

Echo client
-----------
Connects to an echo server, sends a message and disconnect upon reply.

.. code-block:: python

    import asyncio
    import uvloop
    from picows import ws_connect, WSFrame, WSTransport, WSListener, WSMsgType, WSCloseCode

    class ClientListener(WSListener):
        def on_ws_connected(self, transport: WSTransport):
            self.transport = transport
            transport.send(WSMsgType.TEXT, b"Hello world")

        def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
            print(f"Echo reply: {frame.get_payload_as_ascii_text()}")
            transport.send_close(WSCloseCode.OK)
            transport.disconnect()


    async def main(url):
        (_, client) = await ws_connect(ClientListener, url)
        await client.transport.wait_disconnected()


    if __name__ == '__main__':
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        asyncio.run(main("ws://127.0.0.1:9001"))

This prints:

.. code-block::

    Echo reply: Hello world

Echo server
-----------

.. code-block:: python

    import asyncio
    import uvloop
    from picows import ws_create_server, WSFrame, WSTransport, WSListener, WSMsgType, WSUpgradeRequest

    class ServerClientListener(WSListener):
        def on_ws_connected(self, transport: WSTransport):
            print("New client connected")

        def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
            if frame.msg_type == WSMsgType.PING:
                transport.send_pong(frame.get_payload_as_bytes())
            elif frame.msg_type == WSMsgType.CLOSE:
                transport.send_close(frame.get_close_code(), frame.get_close_message())
                transport.disconnect()
            else:
                transport.send(frame.msg_type, frame.get_payload_as_bytes())

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

