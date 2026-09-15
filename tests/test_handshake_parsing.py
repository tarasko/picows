from http import HTTPStatus
from typing import Iterable, Optional, Tuple

import pytest

import picows
from picows.picows import (
    _parse_http_request,
    _parse_upgrade_response,
    _validate_upgrade_request,
)


WEBSOCKET_KEY = b"dGhlIHNhbXBsZSBub25jZQ=="
WEBSOCKET_ACCEPT = b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
VALID_UPGRADE_RESPONSE_HEADERS = (
    b"Upgrade: websocket",
    b"Connection: Upgrade",
    b"Sec-WebSocket-Accept: " + WEBSOCKET_ACCEPT,
)


def make_raw_request(headers: Iterable[bytes] = ()) -> bytes:
    lines = [b"GET /health?ready=true HTTP/1.1"]
    lines.extend(headers)
    return b"\r\n".join(lines)


def test_parse_http_request():
    request = _parse_http_request(make_raw_request([
        b"Host: example.com",
        b"X-Whitespace:\t value \t",
        b"X-Extended: \x80",
    ]))

    assert request.method == b"GET"
    assert request.path == b"/health?ready=true"
    assert request.version == b"HTTP/1.1"
    assert request.headers["Host"] == "example.com"
    assert request.headers["X-Whitespace"] == "value"
    assert request.headers["X-Extended"] == "\udc80"


@pytest.mark.parametrize("request_line", [
    b"",
    b"GET",
    b"GET /health",
    b"GET /health HTTP/1.1 extra",
])
def test_parse_http_request_rejects_malformed_request_line(request_line: bytes):
    with pytest.raises(RuntimeError, match="Malformed request line"):
        _parse_http_request(request_line)


@pytest.mark.parametrize(("request_line", "error"), [
    (b"POST /health HTTP/1.1", "Unsupported HTTP method"),
    (b"GET  HTTP/1.1", "request target cannot be empty"),
    (b"GET /health HTTP/1.0", "Unsupported HTTP version"),
    (b"GET /health HTTP/2", "Unsupported HTTP version"),
])
def test_parse_http_request_rejects_unsupported_request_line(
    request_line: bytes,
    error: str,
):
    with pytest.raises(RuntimeError, match=error):
        _parse_http_request(request_line)


def test_parse_http_request_accepts_all_valid_header_name_characters():
    request = _parse_http_request(make_raw_request([b"!#$%&'*+-.^_`|~: value"]))
    assert request.headers["!#$%&'*+-.^_`|~"] == "value"


@pytest.mark.parametrize("name", [
    b"",
    b"Host ",
    b"Host\t",
    b"Ho(st",
    b"X-Non-ASCII-\x80",
])
def test_parse_http_request_rejects_invalid_header_name(name: bytes):
    with pytest.raises(RuntimeError, match="Invalid HTTP header name"):
        _parse_http_request(make_raw_request([name + b": value"]))


def test_parse_http_request_rejects_header_without_colon():
    with pytest.raises(RuntimeError, match="Malformed header"):
        _parse_http_request(make_raw_request([b"Host example.com"]))


@pytest.mark.parametrize("line", [
    b" Host: example.com",
    b"\tHost: example.com",
])
def test_parse_http_request_rejects_obsolete_folded_header(line: bytes):
    with pytest.raises(RuntimeError, match="Obsolete folded HTTP header"):
        _parse_http_request(make_raw_request([line]))


@pytest.mark.parametrize("value", [
    b"value\x00",
    b"value\x08",
    b"value\n",
    b"value\r",
    b"value\x7f",
])
def test_parse_http_request_rejects_invalid_header_value(value: bytes):
    with pytest.raises(RuntimeError, match="Invalid HTTP header value"):
        _parse_http_request(make_raw_request([b"X-Test: " + value]))


def test_parse_http_request_limits_number_of_headers():
    headers = [f"X-Test-{index}: value".encode() for index in range(128)]
    request = _parse_http_request(make_raw_request(headers))
    assert len(request.headers) == 128

    headers.append(b"X-Test-128: value")
    with pytest.raises(RuntimeError, match="more than 128 headers"):
        _parse_http_request(make_raw_request(headers))


@pytest.mark.parametrize("header", [
    b"Transfer-Encoding: chunked",
    b"transfer-encoding: identity",
])
def test_parse_http_request_rejects_transfer_encoding(header: bytes):
    with pytest.raises(RuntimeError, match="Transfer-Encoding is not supported"):
        _parse_http_request(make_raw_request([header]))


@pytest.mark.parametrize("headers", [
    (),
    (b"Content-Length: 0",),
    (b"Content-Length:\t000\t",),
])
def test_parse_http_request_accepts_no_body(headers: Tuple[bytes, ...]):
    _parse_http_request(make_raw_request(headers))


@pytest.mark.parametrize("value", [
    b"",
    b"-1",
    b"+0",
    b"0, 0",
    b"zero",
    b"1",
    b"01",
])
def test_parse_http_request_rejects_invalid_or_nonzero_content_length(value: bytes):
    with pytest.raises(RuntimeError, match="HTTP request body is not supported"):
        _parse_http_request(make_raw_request([b"Content-Length: " + value]))


def test_parse_http_request_rejects_duplicate_content_length():
    with pytest.raises(RuntimeError, match="Multiple Content-Length"):
        _parse_http_request(make_raw_request([
            b"Content-Length: 0",
            b"Content-Length: 0",
        ]))


def make_upgrade_request(headers: Iterable[bytes]) -> picows.WSUpgradeRequest:
    return _parse_http_request(b"\r\n".join([b"GET / HTTP/1.1", *headers]))


@pytest.mark.parametrize("version", [b"7", b"8", b"13"])
@pytest.mark.parametrize("upgrade", [b"websocket", b"WebSocket", b"WEBSOCKET"])
def test_validate_upgrade_request(version: bytes, upgrade: bytes):
    request = make_upgrade_request([
        b"Upgrade: " + upgrade,
        b"Connection: Upgrade",
        b"Sec-WebSocket-Version: " + version,
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
    ])

    assert _validate_upgrade_request(request) == b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


@pytest.mark.parametrize(("headers", "error"), [
    ((), "No WebSocket UPGRADE header"),
    ((b"Upgrade: h2c",), "No WebSocket UPGRADE header"),
    ((b"Upgrade: websocket",), "No CONNECTION upgrade header"),
    (
        (b"Upgrade: websocket", b"Connection: close"),
        "CONNECTION header value is not 'upgrade'",
    ),
    (
        (b"Upgrade: websocket", b"Connection: Upgrade"),
        "unsupported websocket version",
    ),
    (
        (b"Upgrade: websocket", b"Connection: Upgrade", b"Sec-WebSocket-Version: 12"),
        "unsupported websocket version",
    ),
    (
        (
            b"Upgrade: websocket",
            b"Connection: Upgrade",
            b"Sec-WebSocket-Version: 13",
        ),
        "invalid key",
    ),
    (
        (
            b"Upgrade: websocket",
            b"Connection: Upgrade",
            b"Sec-WebSocket-Version: 13",
            b"Sec-WebSocket-Key: c2hvcnQ=",
        ),
        "invalid key",
    ),
    (
        (
            b"Upgrade: websocket",
            b"Connection: Upgrade",
            b"Sec-WebSocket-Version: 13",
            b"Sec-WebSocket-Key: \x80",
        ),
        "invalid key",
    ),
    (
        (
            b"Upgrade: websocket",
            b"Connection: Upgrade",
            b"Sec-WebSocket-Version: 13",
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==!!!",
        ),
        "invalid key",
    ),
])
def test_validate_upgrade_request_rejects_invalid_headers(
    headers: Tuple[bytes, ...],
    error: str,
):
    request = make_upgrade_request(headers)
    with pytest.raises(RuntimeError, match=error):
        _validate_upgrade_request(request)


def make_upgrade_response(
    status_line: bytes = b"HTTP/1.1 101 Switching Protocols",
    headers: Iterable[bytes] = VALID_UPGRADE_RESPONSE_HEADERS,
    tail: bytes = b"",
) -> bytes:
    return b"\r\n".join([status_line, *headers, b"", tail])


@pytest.mark.parametrize("data", [
    b"",
    b"HTTP/1.1 101 Switching Protocols",
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n",
])
def test_parse_upgrade_response_returns_none_until_headers_are_complete(data: bytes):
    assert _parse_upgrade_response(data, WEBSOCKET_KEY) is None


@pytest.mark.parametrize(("upgrade", "connection"), [
    (b"websocket", b"upgrade"),
    (b"WebSocket", b"Upgrade"),
    (b"WEBSOCKET", b"UPGRADE"),
])
def test_parse_upgrade_response(upgrade: bytes, connection: bytes):
    response = _parse_upgrade_response(
        make_upgrade_response(
            headers=(
                b"Upgrade: " + upgrade,
                b"Connection: " + connection,
                b"Content-Length: 0",
                b"Sec-WebSocket-Accept: " + WEBSOCKET_ACCEPT,
                b"X-Extended: \x80",
            ),
            tail=b"\x81\x00",
        ),
        WEBSOCKET_KEY,
    )

    assert response.version == b"HTTP/1.1"
    assert response.status == HTTPStatus.SWITCHING_PROTOCOLS
    assert response.headers["Upgrade"] == upgrade.decode()
    assert response.headers["Connection"] == connection.decode()
    assert response.headers["X-Extended"] == "\udc80"
    assert response.body is None


@pytest.mark.parametrize(("status_line", "error"), [
    (b"HTTP/1.1 101 \xff", "invalid HTTP status line"),
    (b"HTTP/1.0 101 Switching Protocols", "unknown protocol"),
    (b"HTTP/1.1 invalid Switching Protocols", "invalid HTTP status line"),
])
def test_parse_upgrade_response_rejects_invalid_status_line(status_line: bytes, error: str):
    data = make_upgrade_response(status_line=status_line, tail=b"response body")

    with pytest.raises(picows.WSInvalidMessageError, match=error) as exc_info:
        _parse_upgrade_response(data, WEBSOCKET_KEY)

    assert exc_info.value.raw_header == data.split(b"\r\n\r\n", 1)[0]
    assert exc_info.value.raw_body == b"response body"
    assert exc_info.value.response is None


@pytest.mark.parametrize(("header", "error"), [
    (b"Malformed header", "malformed header"),
    (b" Upgrade: websocket", "Obsolete folded HTTP header"),
    (b"Upgrade : websocket", "Invalid HTTP header name"),
    (b"Bad(Name: value", "Invalid HTTP header name"),
    (b"X-Invalid: ok\x00bad", "Invalid HTTP header value"),
])
def test_parse_upgrade_response_rejects_malformed_header(header: bytes, error: str):
    data = make_upgrade_response(headers=(header,), tail=b"response body")

    with pytest.raises(picows.WSInvalidMessageError, match=error) as exc_info:
        _parse_upgrade_response(data, WEBSOCKET_KEY)

    assert exc_info.value.raw_header == data.split(b"\r\n\r\n", 1)[0]
    assert exc_info.value.raw_body == b"response body"
    assert exc_info.value.response.status == HTTPStatus.SWITCHING_PROTOCOLS


def test_parse_upgrade_response_limits_number_of_headers():
    headers = (*VALID_UPGRADE_RESPONSE_HEADERS, *(b"X-Test: value" for _ in range(126)))

    with pytest.raises(picows.WSInvalidMessageError, match="more than 128 headers"):
        _parse_upgrade_response(make_upgrade_response(headers=headers), WEBSOCKET_KEY)


def test_parse_upgrade_response_rejects_non_switching_protocols_status():
    data = make_upgrade_response(
        status_line=b"HTTP/1.1 400 Bad Request",
        headers=(b"Transfer-Encoding: invalid", b"Content-Length: 11"),
        tail=b"Bad Request",
    )

    with pytest.raises(picows.WSInvalidStatusError, match="received 400") as exc_info:
        _parse_upgrade_response(data, WEBSOCKET_KEY)

    assert exc_info.value.raw_body == b"Bad Request"
    assert exc_info.value.response.status == HTTPStatus.BAD_REQUEST


@pytest.mark.parametrize("transfer_encoding", [b"chunked", b"Chunked", b"gzip"])
def test_parse_upgrade_response_rejects_transfer_encoding(transfer_encoding: bytes):
    headers = (*VALID_UPGRADE_RESPONSE_HEADERS, b"Transfer-Encoding: " + transfer_encoding)

    with pytest.raises(picows.WSInvalidHeaderError, match="Transfer-Encoding") as exc_info:
        _parse_upgrade_response(make_upgrade_response(headers=headers), WEBSOCKET_KEY)

    assert exc_info.value.name == "Transfer-Encoding"
    assert exc_info.value.value == transfer_encoding.decode()


@pytest.mark.parametrize(("content_length", "error"), [
    (b"invalid", "invalid Content-Length"),
    (b"1", "non-zero Content-Length"),
])
def test_parse_upgrade_response_rejects_invalid_content_length(content_length: bytes, error: str):
    headers = (*VALID_UPGRADE_RESPONSE_HEADERS, b"Content-Length: " + content_length)

    with pytest.raises(picows.WSInvalidHeaderError, match=error) as exc_info:
        _parse_upgrade_response(make_upgrade_response(headers=headers), WEBSOCKET_KEY)

    assert exc_info.value.name == "Content-Length"
    assert exc_info.value.value == content_length.decode()


@pytest.mark.parametrize("upgrade", [None, b"not-websocket"])
def test_parse_upgrade_response_rejects_invalid_upgrade_header(upgrade: Optional[bytes]):
    headers = [
        b"Connection: Upgrade",
        b"Sec-WebSocket-Accept: " + WEBSOCKET_ACCEPT,
    ]
    if upgrade is not None:
        headers.append(b"Upgrade: " + upgrade)

    with pytest.raises(picows.WSInvalidUpgradeError, match="invalid upgrade header") as exc_info:
        _parse_upgrade_response(make_upgrade_response(headers=headers), WEBSOCKET_KEY)

    assert exc_info.value.name == "Upgrade"
    expected_value = None if upgrade is None else upgrade.decode()
    assert exc_info.value.value == expected_value


@pytest.mark.parametrize("connection", [None, b"close"])
def test_parse_upgrade_response_rejects_invalid_connection_header(connection: Optional[bytes]):
    headers = [
        b"Upgrade: websocket",
        b"Sec-WebSocket-Accept: " + WEBSOCKET_ACCEPT,
    ]
    if connection is not None:
        headers.append(b"Connection: " + connection)

    with pytest.raises(picows.WSInvalidUpgradeError, match="invalid connection header") as exc_info:
        _parse_upgrade_response(make_upgrade_response(headers=headers), WEBSOCKET_KEY)

    assert exc_info.value.name == "Connection"
    expected_value = None if connection is None else connection.decode()
    assert exc_info.value.value == expected_value


@pytest.mark.parametrize("accept", [None, b"invalid"])
def test_parse_upgrade_response_rejects_invalid_accept_header(accept: Optional[bytes]):
    headers = [b"Upgrade: websocket", b"Connection: Upgrade"]
    if accept is not None:
        headers.append(b"Sec-WebSocket-Accept: " + accept)

    with pytest.raises(picows.WSInvalidHeaderError, match="invalid sec-websocket-accept") as exc_info:
        _parse_upgrade_response(make_upgrade_response(headers=headers), WEBSOCKET_KEY)

    assert exc_info.value.name == "Sec-WebSocket-Accept"
    expected_value = None if accept is None else accept.decode()
    assert exc_info.value.value == expected_value
