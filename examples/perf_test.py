# Use this script to run under perf and analyze performance and record call graph stats
# $ perf record -F 999 -g --call-graph lbr --user-callchains -- python -m examples.perf_test --msg-size 8192 --ssl
# After recording, view it with
# $ perf report -G -n --stdio

import argparse
import asyncio
import ssl

from picows import ws_connect
from examples.echo_client_cython import ClientListenerCython

def create_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


async def main(url, msg_size, duration, **kwargs):
    transport, client = await ws_connect(
        lambda: ClientListenerCython(msg_size, duration),
        url,
        **kwargs)
    await transport.wait_disconnected()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run client in the loop with different options",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--tcp-port", type=int, default="9001", help="Server port with plain tcp websockets")
    parser.add_argument("--ssl-port", type=int, default="9002", help="Server port with ssl websockets")
    parser.add_argument("--msg-size", type=int, default="256", help="Message size")
    parser.add_argument("--duration", type=int, default="10", help="duration of test in seconds")
    parser.add_argument("--disable-aiofastnet", action="store_true", help="Disable aiofastnet usage")
    parser.add_argument("--loop", default="uvloop", help="One of [asyncio,uvloop]")
    parser.add_argument("--ssl", action="store_true", help="Run ssl client, if not specified, run tcp client")

    args = parser.parse_args()

    ssl_context = create_client_ssl_context() if args.ssl else None
    url = f"{'wss' if args.ssl else 'ws'}://{args.host}:{args.ssl_port if args.ssl else args.tcp_port}/"
    use_aiofastnet = not args.disable_aiofastnet

    if args.loop == "uvloop":
        import uvloop
        uvloop.install()

    asyncio.run(main(url, args.msg_size, args.duration,
                     ssl_context=ssl_context,
                     use_aiofastnet=use_aiofastnet))
