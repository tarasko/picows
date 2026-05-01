from __future__ import annotations

from typing import Any, Optional


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


class InvalidHandshake(WebSocketException):
    pass


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


class ProtocolError(WebSocketException):
    pass


class PayloadTooBig(WebSocketException):
    pass


class InvalidState(WebSocketException):
    pass


class ConcurrencyError(WebSocketException):
    pass
