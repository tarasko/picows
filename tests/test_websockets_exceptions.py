from dataclasses import dataclass

from multidict import CIMultiDict

from picows import websockets


@dataclass
class Close:
    code: int
    reason: str


def test_connection_closed_string_variants():
    assert str(websockets.ConnectionClosed(None, None)) == "no close frame received or sent"
    assert str(websockets.ConnectionClosed(None, Close(1000, "bye"))) == "sent 1000 (bye)"
    assert str(websockets.ConnectionClosed(Close(1001, "away"), None)) == "received 1001 (away)"
    assert str(websockets.ConnectionClosed(Close(1001, "away"), Close(1000, "bye"), True)) == (
        "received then sent close frames: received 1001 (away), sent 1000 (bye)"
    )
    assert str(websockets.ConnectionClosed(Close(1001, "away"), Close(1000, "bye"), False)) == (
        "sent then received close frames: received 1001 (away), sent 1000 (bye)"
    )


def test_exception_attributes_and_strings():
    assert str(websockets.InvalidURI("http://example.com", "wrong scheme")) == (
        "http://example.com isn't a valid WebSocket URI: wrong scheme"
    )
    assert str(websockets.InvalidProxy("ftp://proxy", "wrong scheme")) == (
        "ftp://proxy isn't a valid proxy: wrong scheme"
    )
    assert str(websockets.InvalidProxyStatus(object())) == "proxy rejected connection"
    assert str(websockets.InvalidProxyStatus(websockets.Response(502, "Bad Gateway", CIMultiDict(), b""))) == (
        "proxy rejected connection: HTTP 502"
    )

    invalid_header = websockets.InvalidHeader("X-Test", "bad")
    assert invalid_header.name == "X-Test"
    assert invalid_header.value == "bad"
    assert websockets.InvalidOrigin("https://bad.example").name == "Origin"
    assert websockets.InvalidHeaderFormat("X-Test", "bad syntax", "x:y", 1).value == "bad syntax at 1 in x:y"

    assert str(websockets.DuplicateParameter("server_max_window_bits")) == (
        "duplicate parameter: server_max_window_bits"
    )
    assert str(websockets.InvalidParameterName("x")) == "invalid parameter name: x"
    assert str(websockets.InvalidParameterValue("x", None)) == "missing value for parameter x"
    assert str(websockets.InvalidParameterValue("x", "")) == "empty value for parameter x"
    assert str(websockets.InvalidParameterValue("x", "bad")) == "invalid value for parameter x: bad"
