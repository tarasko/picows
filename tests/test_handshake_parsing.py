from typing import Iterable, Tuple

import pytest

import picows
from picows.picows import _parse_http_request, _validate_upgrade_request


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
def test_validate_upgrade_request(version: bytes):
    request = make_upgrade_request([
        b"Upgrade: websocket",
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
])
def test_validate_upgrade_request_rejects_invalid_headers(
    headers: Tuple[bytes, ...],
    error: str,
):
    request = make_upgrade_request(headers)
    with pytest.raises(RuntimeError, match=error):
        _validate_upgrade_request(request)
