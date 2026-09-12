import asyncio
import base64
from typing import Optional, Tuple
from unittest.mock import Mock

import pytest
from python_socks import ProxyError

from picows import proxy
from picows.proxy import HTTPProxyConnectProtocol


def make_protocol(
        host: str = "example.com",
        port: int = 443,
        username: Optional[str] = None,
        password: Optional[str] = None,
) -> Tuple[HTTPProxyConnectProtocol, Mock]:
    protocol = HTTPProxyConnectProtocol(host, port, username, password)
    transport = Mock(spec=asyncio.Transport)
    protocol.connection_made(transport)
    return protocol, transport


@pytest.mark.parametrize(("host", "username", "password", "authority", "credentials"), [
    ("example.com", None, None, "example.com:443", None),
    ("2001:db8::1", "user%40example.com", "pa%3Ass", "[2001:db8::1]:443", "user@example.com:pa:ss"),
    ("[2001:db8::1]", "user", None, "[2001:db8::1]:443", "user:"),
])
async def test_connection_made_writes_connect_request(
        host: str,
        username: Optional[str],
        password: Optional[str],
        authority: str,
        credentials: Optional[str],
) -> None:
    _, transport = make_protocol(host=host, username=username, password=password)
    expected = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n".encode("ascii")
    if credentials is not None:
        encoded_credentials = base64.b64encode(credentials.encode()).decode("ascii")
        expected += f"Proxy-Authorization: Basic {encoded_credentials}\r\n".encode("ascii")

    transport.write.assert_called_once_with(expected + b"\r\n")


async def test_data_received_accepts_fragmented_success_and_ignores_later_data() -> None:
    protocol, transport = make_protocol()

    protocol.data_received(b"HTTP/1.1 2")
    assert not protocol._tunnel_established.done()

    protocol.data_received(b"00 Connection established\r\nX-Proxy: test\r\n\r\n")
    await protocol.wait_tunnel_established()

    protocol.data_received(b"data from the server")
    transport.abort.assert_not_called()


@pytest.mark.parametrize(("response", "connect_transport"), [
    pytest.param(b"x" * (proxy._MAX_PROXY_RESPONSE_SIZE + 1), True, id="unterminated"),
    pytest.param(
        b"x" * (proxy._MAX_PROXY_RESPONSE_SIZE + 1) + b"\r\n\r\n",
        False,
        id="terminator-beyond-limit",
    ),
])
async def test_data_received_rejects_oversized_headers(response: bytes, connect_transport: bool) -> None:
    protocol = HTTPProxyConnectProtocol("example.com", 443, None, None)
    transport = Mock(spec=asyncio.Transport)
    if connect_transport:
        protocol.connection_made(transport)

    protocol.data_received(response)

    with pytest.raises(ProxyError, match="response headers are too large"):
        await protocol.wait_tunnel_established()
    if connect_transport:
        transport.abort.assert_called_once_with()
    else:
        transport.abort.assert_not_called()


@pytest.mark.parametrize("status_line", [
    b"",
    b"NOT-HTTP 200 OK",
    b"HTTP/1.1 not-a-status",
])
async def test_data_received_rejects_invalid_status_line(status_line: bytes) -> None:
    protocol, transport = make_protocol()

    protocol.data_received(status_line + b"\r\n\r\n")

    with pytest.raises(ProxyError, match="HTTP proxy returned an invalid response"):
        await protocol.wait_tunnel_established()
    transport.abort.assert_called_once_with()


@pytest.mark.parametrize("status", [200, 299])
async def test_data_received_accepts_success_status(status: int) -> None:
    protocol, transport = make_protocol()

    protocol.data_received(f"HTTP/1.1 {status} Proxy reply\r\n\r\n".encode("ascii"))

    await protocol.wait_tunnel_established()
    transport.abort.assert_not_called()


@pytest.mark.parametrize("status", [199, 300, 407])
async def test_data_received_rejects_non_success_status(status: int) -> None:
    protocol, transport = make_protocol()

    protocol.data_received(f"HTTP/1.1 {status} Proxy reply\r\n\r\n".encode("ascii"))

    with pytest.raises(ProxyError, match=f"HTTP proxy rejected connection with status {status}"):
        await protocol.wait_tunnel_established()
    transport.abort.assert_called_once_with()


@pytest.mark.parametrize("exc", [None, RuntimeError("connection failed")])
async def test_connection_lost_before_reply_fails_waiter(exc: Optional[Exception]) -> None:
    protocol, transport = make_protocol()

    protocol.connection_lost(exc)

    if exc is None:
        with pytest.raises(ProxyError, match="HTTP proxy closed the connection before replying"):
            await protocol.wait_tunnel_established()
    else:
        with pytest.raises(RuntimeError, match="connection failed") as raised:
            await protocol.wait_tunnel_established()
        assert raised.value is exc
    transport.abort.assert_not_called()


async def test_connection_lost_after_reply_is_ignored() -> None:
    protocol, transport = make_protocol()
    protocol.data_received(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await protocol.wait_tunnel_established()

    protocol.connection_lost(RuntimeError("connection failed"))

    await protocol.wait_tunnel_established()
    transport.abort.assert_not_called()
