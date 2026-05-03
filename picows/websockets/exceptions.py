from __future__ import annotations

from typing import Any, Optional

__all__ = [
    "WebSocketException",
    "ConnectionClosed",
    "ConnectionClosedOK",
    "ConnectionClosedError",
    "InvalidURI",
    "InvalidProxy",
    "InvalidHandshake",
    "SecurityError",
    "ProxyError",
    "InvalidProxyMessage",
    "InvalidProxyStatus",
    "InvalidMessage",
    "InvalidStatus",
    "InvalidHeader",
    "InvalidHeaderFormat",
    "InvalidHeaderValue",
    "InvalidOrigin",
    "InvalidUpgrade",
    "NegotiationError",
    "DuplicateParameter",
    "InvalidParameterName",
    "InvalidParameterValue",
    "ProtocolError",
    "PayloadTooBig",
    "InvalidState",
    "ConcurrencyError",
]


class WebSocketException(Exception):
    """Base class for exceptions defined by picows.websockets."""


class ConnectionClosed(WebSocketException):
    def __init__(self, rcvd: Any, sent: Any, rcvd_then_sent: Optional[bool] = None):
        super().__init__()
        self.rcvd = rcvd
        self.sent = sent
        self.rcvd_then_sent = rcvd_then_sent

    def __str__(self) -> str:
        if self.rcvd is None and self.sent is None:
            return "no close frame received or sent"
        if self.rcvd is None:
            return f"sent {self.sent.code} ({self.sent.reason})"
        if self.sent is None:
            return f"received {self.rcvd.code} ({self.rcvd.reason})"
        order = "received then sent" if self.rcvd_then_sent else "sent then received"
        return (
            f"{order} close frames: "
            f"received {self.rcvd.code} ({self.rcvd.reason}), "
            f"sent {self.sent.code} ({self.sent.reason})"
        )


class ConnectionClosedOK(ConnectionClosed):
    pass


class ConnectionClosedError(ConnectionClosed):
    pass


class InvalidURI(WebSocketException):
    def __init__(self, uri: str, msg: str):
        super().__init__(uri, msg)
        self.uri = uri
        self.msg = msg

    def __str__(self) -> str:
        return f"{self.uri} isn't a valid WebSocket URI: {self.msg}"


class InvalidProxy(WebSocketException):
    def __init__(self, proxy: str, msg: str):
        super().__init__(proxy, msg)
        self.proxy = proxy
        self.msg = msg

    def __str__(self) -> str:
        return f"{self.proxy} isn't a valid proxy: {self.msg}"


class InvalidHandshake(WebSocketException):
    pass


class SecurityError(InvalidHandshake):
    pass


class ProxyError(InvalidHandshake):
    pass


class InvalidProxyMessage(ProxyError):
    pass


class InvalidProxyStatus(ProxyError):
    def __init__(self, response: Any):
        super().__init__(response)
        self.response = response

    def __str__(self) -> str:
        status = getattr(self.response, "status", None)
        if status is None:
            return "proxy rejected connection"
        return f"proxy rejected connection: HTTP {int(status):d}"


class InvalidMessage(InvalidHandshake):
    pass


class InvalidStatus(InvalidHandshake):
    def __init__(self, response: Any):
        super().__init__(response)
        self.response = response


class InvalidHeader(InvalidHandshake):
    def __init__(self, name: str, value: Optional[str] = None):
        super().__init__(name, value)
        self.name = name
        self.value = value


class InvalidUpgrade(InvalidHeader):
    pass


class InvalidHeaderFormat(InvalidHeader):
    def __init__(self, name: str, error: str, header: str, pos: int):
        super().__init__(name, f"{error} at {pos} in {header}")


class InvalidHeaderValue(InvalidHeader):
    pass


class InvalidOrigin(InvalidHeader):
    def __init__(self, origin: Optional[str]):
        super().__init__("Origin", origin)


class NegotiationError(InvalidHandshake):
    pass


class DuplicateParameter(NegotiationError):
    def __init__(self, name: str):
        super().__init__(name)
        self.name = name

    def __str__(self) -> str:
        return f"duplicate parameter: {self.name}"


class InvalidParameterName(NegotiationError):
    def __init__(self, name: str):
        super().__init__(name)
        self.name = name

    def __str__(self) -> str:
        return f"invalid parameter name: {self.name}"


class InvalidParameterValue(NegotiationError):
    def __init__(self, name: str, value: Optional[str]):
        super().__init__(name, value)
        self.name = name
        self.value = value

    def __str__(self) -> str:
        if self.value is None:
            return f"missing value for parameter {self.name}"
        if self.value == "":
            return f"empty value for parameter {self.name}"
        return f"invalid value for parameter {self.name}: {self.value}"


class ProtocolError(WebSocketException):
    pass


class PayloadTooBig(WebSocketException):
    pass


class InvalidState(WebSocketException, AssertionError):
    pass


class ConcurrencyError(WebSocketException, RuntimeError):
    pass
