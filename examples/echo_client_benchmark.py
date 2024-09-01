import argparse
import asyncio
import os
import ssl
import subprocess

from logging import getLogger
from ssl import SSLContext

import websockets
import aiohttp
from aiohttp import ClientSession, WSMsgType as aiohttp_WSMsgType

from picows import WSFrame, WSTransport, WSListener, ws_connect, WSMsgType
from time import time

_logger = getLogger(__name__)


RPS = {}


def create_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


async def picows_main(endpoint: str, msg: bytes, duration: int, ssl_context):
    print(f"Run picows python client")
    class PicowsClientListener(WSListener):
        def __init__(self):
            super().__init__()
            self._full_msg = bytearray()

        def on_ws_connected(self, transport: WSTransport):
            self._transport = transport
            self._start_time = time()
            self._cnt = 0
            self._transport.send(WSMsgType.BINARY, msg)

        def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
            if frame.fin:
                if self._full_msg:
                    self._full_msg += frame.get_payload_as_memoryview()
                    self._full_msg.clear()
                else:
                    pass
            else:
                self._full_msg += frame.get_payload_as_memoryview()
                return

            self._cnt += 1

            if time() - self._start_time >= duration:
                RPS["picows\npython client"] = int(self._cnt / duration)
                self._transport.disconnect()
            else:
                self._transport.send(WSMsgType.BINARY, msg)

    (_, client) = await ws_connect(PicowsClientListener, endpoint, ssl_context=ssl_context)
    await client._transport.wait_disconnected()


async def websockets_main(endpoint: str, msg: bytes, duration: int, ssl_context):
    print(f"Run websockets ({websockets.__version__}) client")
    async with websockets.connect(endpoint, ssl=ssl_context) as websocket:
        await websocket.send(msg)
        start_time = time()
        cnt = 0
        while True:
            reply = await websocket.recv()
            assert reply == msg
            cnt += 1
            if time() - start_time >= duration:
                break
            else:
                await websocket.send(msg)

        RPS[f"websockets\n{websockets.__version__}"] = int(cnt / duration)


async def aiohttp_main(url: str, data: bytes, duration: int, ssl_context) -> None:
    print(f"Run aiohttp ({aiohttp.__version__}) client")

    async with ClientSession() as session:
        async with session.ws_connect(url, ssl_context=ssl_context) as ws:
            # send request
            cnt = 0
            start_time = time()
            await ws.send_bytes(data)

            while True:
                msg = await ws.receive()

                if msg.type == aiohttp_WSMsgType.BINARY:
                    cnt += 1
                    if time() - start_time >= duration:
                        RPS[f"aiohttp\n{aiohttp.__version__}"] = int(cnt/duration)
                        await ws.close()
                    else:
                        await ws.send_bytes(data)
                else:
                    if msg.type == aiohttp_WSMsgType.CLOSE:
                        await ws.close()
                    elif msg.type == aiohttp_WSMsgType.ERROR:
                        print("Error during receive %s" % ws.exception())
                    elif msg.type == aiohttp_WSMsgType.CLOSED:
                        pass

                    break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Publish updates to telegram subscribers",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--url", default="ws://127.0.0.1:9001", help="Server url")
    parser.add_argument("--msg-size", default="256", help="Message size")
    parser.add_argument("--level", default="INFO", help="python logger level")
    parser.add_argument("--duration", default="5", help="duration of test in seconds")
    parser.add_argument("--disable-uvloop", action="store_true", help="Disable uvloop")
    parser.add_argument("--boost-client", help="Path to boost client binary")
    parser.add_argument("--log-file", help="tee log to file")
    parser.add_argument("--log-scale", action="store_true", help="Plot RPS on log scale")
    args = parser.parse_args()

    msg_size = int(args.msg_size)
    msg = os.urandom(msg_size)
    duration = int(args.duration)

    loop_name = "asyncio"
    if not args.disable_uvloop:
        if os.name != 'nt':
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            loop_name = f"uvloop {uvloop.__version__}"

    ssl_context = create_client_ssl_context() if args.url.startswith("wss://") else None

    asyncio.run(websockets_main(args.url, msg, duration, ssl_context))
    asyncio.run(aiohttp_main(args.url, msg, duration, ssl_context))
    asyncio.run(picows_main(args.url, msg, duration, ssl_context))

    try:
        from examples.echo_client_cython import picows_main_cython
        print(f"Run picows cython client")
        picows_cython_rps = asyncio.run(picows_main_cython(args.url, msg, duration, ssl_context))
        RPS["picows\ncython client"] = picows_cython_rps
    except ImportError:
        pass

    if args.boost_client is not None:
        print(f"Run boost.beast client")
        pr = subprocess.run([args.boost_client, b"127.0.0.1", b"9001", args.msg_size, args.duration],
                            shell=False, check=True, capture_output=True)
        name, rps = pr.stdout.split(b":", 2)
        RPS[f"c++ boost.beast\n{name.decode()}"] = int(rps.decode())

    for k, v in RPS.items():
        print(k.replace("\n", " "), v)

    try:
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots()

        libraries = list(RPS.keys())
        counts = list(RPS.values())
        bar_colors = ['tab:red', 'tab:orange', 'tab:green', 'tab:green', 'tab:blue']

        ax.bar(libraries, counts, label=libraries, color=bar_colors)

        ax.set_ylabel('request/second')
        if args.log_scale:
            ax.set_yscale('log')
            ax.set_yticks([counts[0]/2, 10000, 20000, 30000, 40000])
        ax.set_title(f'Echo round-trip performance \n({loop_name}, msg_size={msg_size})')

        # ax.legend(title="Libraries")

        plt.show()
    except ImportError:
        pass
