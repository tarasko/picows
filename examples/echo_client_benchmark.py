import argparse
import asyncio
import os
import platform
import ssl
import subprocess

from logging import getLogger
from typing import List, Dict

import numpy as np
import websockets
import aiohttp
from aiohttp import ClientSession, WSMsgType as aiohttp_WSMsgType

from picows import WSFrame, WSTransport, WSListener, ws_connect, WSMsgType
from time import time


try:
    from examples.echo_client_cython import picows_main_cython
except ImportError:
    picows_main_cython = None


RPS: Dict[str, List[float]] = {"ssl": [], "plain": []}
NAMES: List[str] = []
_logger = getLogger(__name__)


def create_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


async def picows_main(endpoint: str, msg: bytes, duration: int, ssl_context):
    cl_type = "plain" if ssl_context is None else "ssl"
    print(f"Run picows python {cl_type} client")

    class PicowsClientListener(WSListener):
        _transport: WSTransport
        _start_time: float
        _cnt: int

        def __init__(self):
            super().__init__()

        def on_ws_connected(self, transport: WSTransport):
            self._transport = transport
            self._start_time = time()
            self._cnt = 0
            self._transport.send(WSMsgType.BINARY, msg)

        def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
            self._cnt += 1

            if time() - self._start_time >= duration:
                self.result = "picows\npython client", int(self._cnt / duration)
                self._transport.disconnect()
            else:
                self._transport.send(WSMsgType.BINARY, msg)

    (_, client) = await ws_connect(PicowsClientListener, endpoint, ssl_context=ssl_context)
    await client._transport.wait_disconnected()
    return client.result


async def websockets_main(endpoint: str, msg: bytes, duration: int, ssl_context):
    cl_type = "plain" if ssl_context is None else "ssl"

    print(f"Run websockets ({websockets.__version__}) {cl_type} client")
    async with websockets.connect(
        endpoint,
        ssl=ssl_context,
        compression=None,
        max_queue=None,
        max_size=None,
        ping_interval=None,
    ) as websocket:
        await websocket.send(msg)
        start_time = time()
        cnt = 0
        while True:
            await websocket.recv()
            cnt += 1
            if time() - start_time >= duration:
                break
            else:
                await websocket.send(msg)

        return f"websockets\n{websockets.__version__}",  int(cnt / duration)


async def aiohttp_main(url: str, data: bytes, duration: int, ssl_context):
    cl_type = "plain" if ssl_context is None else "ssl"

    print(f"Run aiohttp ({aiohttp.__version__}) {cl_type} client")

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
                        await ws.close()
                        return f"aiohttp\n{aiohttp.__version__}", int(cnt/duration)
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


def run_for_websockets_library(plain_url, ssl_url, ssl_context, msg, duration):
    _, rps = asyncio.run(websockets_main(plain_url, msg, duration, None))
    RPS["plain"].append(rps)
    name, rps = asyncio.run(websockets_main(ssl_url, msg, duration, ssl_context))
    RPS["ssl"].append(rps)
    NAMES.append(name)


def run_for_aiohttp_library(plain_url, ssl_url, ssl_context, msg, duration):
    _, rps = asyncio.run(aiohttp_main(plain_url, msg, duration, None))
    RPS["plain"].append(rps)
    name, rps = asyncio.run(aiohttp_main(ssl_url, msg, duration, ssl_context))
    RPS["ssl"].append(rps)
    NAMES.append(name)


def run_picows_client(plain_url, ssl_url, ssl_context, msg, duration):
    _, rps = asyncio.run(picows_main(plain_url, msg, duration, None))
    RPS["plain"].append(rps)
    name, rps = asyncio.run(picows_main(ssl_url, msg, duration, ssl_context))
    RPS["ssl"].append(rps)
    NAMES.append(name)


def run_picows_cython_plain_client(plain_url, ssl_url, ssl_context, msg, duration):
    print("Run picows cython plain client")
    rps = asyncio.run(picows_main_cython(plain_url, msg, duration, None))
    RPS["plain"].append(rps)


def run_picows_cython_ssl_client(plain_url, ssl_url, ssl_context, msg, duration):
    print("Run picows cython ssl client")
    rps = asyncio.run(picows_main_cython(ssl_url, msg, duration, ssl_context))
    RPS["ssl"].append(rps)


def run_boost_beast_client(args):
    print("Run boost.beast plain client")
    pr = subprocess.run([args.boost_client, b"0",
                         args.host.encode(),
                         args.plain_port.encode(),
                         args.msg_size, args.duration],
                        shell=False, check=True, capture_output=True)
    _, rps = pr.stdout.split(b":", 2)
    RPS["plain"].append(int(rps.decode()))

    print("Run boost.beast ssl client")
    pr = subprocess.run([args.boost_client, b"1",
                         args.host.encode(),
                         args.ssl_port.encode(),
                         args.msg_size, args.duration],
                        shell=False, check=True, capture_output=True)
    name, rps = pr.stdout.split(b":", 2)
    RPS["ssl"].append(int(rps.decode()))
    NAMES.append("c++ boost.beast")


def print_result_and_plot(loop_name, msg_size):
    for k, v in RPS.items():
        print(k.replace("\n", " "), v)

    print("names:", " | ".join(n.replace("\n", " ") for n in NAMES))

    try:
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(layout='constrained')

        x = np.arange(len(NAMES))
        width = 0.25  # the width of the bars
        multiplier = 0

        for cl_type, measurement in RPS.items():
            offset = width * multiplier
            ax.bar(x + offset, measurement, width, label=cl_type)
            multiplier += 1

        ax.set_ylabel('request/second')
        ax.set_title(f'Echo round-trip performance \n(python {platform.python_version()}, {loop_name}, msg_size={msg_size})')
        ax.set_xticks(x + width, NAMES)
        ax.legend(loc='upper left', ncols=3)

        plt.show()
    except ImportError:
        pass


def main():
    parser = argparse.ArgumentParser(description="Benchmark for the various websocket clients",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--plain-port", default="9001", help="Server port with plain websockets")
    parser.add_argument("--ssl-port", default="9002", help="Server port with secure websockets")
    parser.add_argument("--msg-size", default="256", help="Message size")
    parser.add_argument("--duration", default="5", help="duration of test in seconds")
    parser.add_argument("--disable-uvloop", action="store_true", help="Disable uvloop")
    parser.add_argument("--picows-plain-only", action="store_true", help="Run only plain picows cython client")
    parser.add_argument("--picows-ssl-only", action="store_true", help="Run only ssl picows cython client")
    parser.add_argument("--boost-client", help="Path to boost client binary")
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

    ssl_context = create_client_ssl_context()
    plain_url = f"ws://{args.host}:{args.plain_port}/"
    ssl_url = f"wss://{args.host}:{args.ssl_port}/"

    if not args.picows_plain_only and not args.picows_ssl_only:
        run_for_websockets_library(plain_url, ssl_url, ssl_context, msg, duration)
        run_for_aiohttp_library(plain_url, ssl_url, ssl_context, msg, duration)
        run_picows_client(plain_url, ssl_url, ssl_context, msg, duration)

    if picows_main_cython is not None:
        NAMES.append("picows\ncython client")

        if not args.picows_ssl_only:
            run_picows_cython_plain_client(plain_url, ssl_url, ssl_context, msg, duration)

        if not args.picows_plain_only:
            run_picows_cython_ssl_client(plain_url, ssl_url, ssl_context, msg, duration)

    if not args.picows_plain_only and not args.picows_ssl_only and args.boost_client is not None:
        run_boost_beast_client(args)

    if args.picows_plain_only or args.picows_ssl_only:
        exit()

    print_result_and_plot(loop_name, msg_size)


if __name__ == '__main__':
    main()
