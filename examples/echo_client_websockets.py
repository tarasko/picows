import asyncio

from picows import websockets


async def main():
    async with websockets.connect("ws://127.0.0.1:9001") as websocket:
        await websocket.send("Hello world")
        reply = await websocket.recv()
        print(f"Echo reply: {reply}")


if __name__ == "__main__":
    asyncio.run(main())
