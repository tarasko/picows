import asyncio
import os

import picows
from picows import ws_create_server, ws_connect, WSMsgType, WSCloseCode
from picows.url import parse_url


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _EchoServerListener(picows.WSListener):
    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        if frame.msg_type == WSMsgType.CLOSE:
            transport.send_close(frame.get_close_code(), frame.get_close_message())
            transport.disconnect()
        else:
            transport.send(frame.msg_type, frame.get_payload_as_bytes())


class _BenchClient(picows.WSListener):
    def __init__(self):
        self._received = asyncio.Event()
        self._count = 0
        self._target = 0

    def on_ws_connected(self, transport: picows.WSTransport):
        self.transport = transport

    def on_ws_frame(self, transport: picows.WSTransport, frame: picows.WSFrame):
        self._count += 1
        if self._count >= self._target:
            self._received.set()

    async def wait_for(self, n: int):
        self._count = 0
        self._target = n
        self._received.clear()
        await self._received.wait()


async def _echo_roundtrip(msg: bytes, iterations: int):
    """Send *iterations* messages through a loopback echo server and wait for all replies."""
    server = await ws_create_server(
        lambda _: _EchoServerListener(),
        "127.0.0.1", 0,
        websocket_handshake_timeout=5,
        enable_auto_pong=False,
    )
    port = server.sockets[0].getsockname()[1]
    url = f"ws://127.0.0.1:{port}/"

    transport, client = await ws_connect(
        _BenchClient,
        url,
        websocket_handshake_timeout=5,
        enable_auto_pong=False,
    )

    try:
        for _ in range(iterations):
            transport.send(WSMsgType.BINARY, msg)
        await client.wait_for(iterations)
    finally:
        transport.disconnect(False)
        try:
            await transport.wait_disconnected()
        except Exception:
            pass
        server.close()
        await server.wait_closed()


# ---------------------------------------------------------------------------
# URL parsing benchmarks
# ---------------------------------------------------------------------------

def test_bench_parse_url_simple(benchmark):
    """Benchmark parsing a simple WebSocket URL."""
    benchmark(parse_url, "ws://example.com/path")


def test_bench_parse_url_with_query(benchmark):
    """Benchmark parsing a URL with query parameters."""
    benchmark(parse_url, "wss://example.com:8443/v1/ws?token=abc123&mode=fast")


# ---------------------------------------------------------------------------
# Echo roundtrip benchmarks (various payload sizes)
# ---------------------------------------------------------------------------

def test_bench_echo_roundtrip_small(benchmark):
    """Benchmark echo roundtrip with a small (64 byte) message."""
    msg = b"A" * 64

    def run():
        asyncio.get_event_loop().run_until_complete(_echo_roundtrip(msg, 100))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        benchmark.pedantic(run, rounds=5, iterations=1)
    finally:
        loop.close()


def test_bench_echo_roundtrip_medium(benchmark):
    """Benchmark echo roundtrip with a medium (4 KB) message."""
    msg = b"B" * 4096

    def run():
        asyncio.get_event_loop().run_until_complete(_echo_roundtrip(msg, 100))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        benchmark.pedantic(run, rounds=5, iterations=1)
    finally:
        loop.close()


def test_bench_echo_roundtrip_large(benchmark):
    """Benchmark echo roundtrip with a large (64 KB) message."""
    msg = b"C" * 65536

    def run():
        asyncio.get_event_loop().run_until_complete(_echo_roundtrip(msg, 50))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        benchmark.pedantic(run, rounds=5, iterations=1)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Frame send benchmarks (measure frame building / sending throughput)
# ---------------------------------------------------------------------------

async def _send_frames(msg: bytes, count: int):
    """Connect to an echo server and send *count* frames as fast as possible."""
    server = await ws_create_server(
        lambda _: _EchoServerListener(),
        "127.0.0.1", 0,
        websocket_handshake_timeout=5,
        enable_auto_pong=False,
    )
    port = server.sockets[0].getsockname()[1]
    url = f"ws://127.0.0.1:{port}/"

    transport, client = await ws_connect(
        _BenchClient,
        url,
        websocket_handshake_timeout=5,
        enable_auto_pong=False,
    )

    try:
        for _ in range(count):
            transport.send(WSMsgType.BINARY, msg)
        await client.wait_for(count)
    finally:
        transport.disconnect(False)
        try:
            await transport.wait_disconnected()
        except Exception:
            pass
        server.close()
        await server.wait_closed()


def test_bench_send_many_small_frames(benchmark):
    """Benchmark sending 1000 small (32 byte) frames."""
    msg = b"X" * 32

    def run():
        asyncio.get_event_loop().run_until_complete(_send_frames(msg, 1000))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        benchmark.pedantic(run, rounds=5, iterations=1)
    finally:
        loop.close()
