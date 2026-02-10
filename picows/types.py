from http import HTTPStatus
from typing import Union, Optional, Mapping, Iterable, Final, cast

from multidict import CIMultiDict, istr

PICOWS_DEBUG_LL: Final = 9
WSHeadersLike = Union[Mapping[str, str], Iterable[tuple[str, str]]]


def add_extra_headers(headers, extra_headers: WSHeadersLike):
    if extra_headers:
        sequence = extra_headers.items() if hasattr(extra_headers,
                                                    "items") else extra_headers
        for k, v in sequence:
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("extra_headers key/value must be str types")

            headers.add(k, v)


class WSUpgradeRequest:
    method  : bytes
    path    : bytes
    version : bytes
    headers : CIMultiDict[istr, str]


class WSUpgradeResponse:
    version : bytes
    status  : HTTPStatus
    headers : CIMultiDict[istr, str]
    body    : Optional[bytes]

    @staticmethod
    def create_error_response(status: Union[int, HTTPStatus],
                              body=None,
                              extra_headers: Optional[WSHeadersLike]=None):
        """
        Create upgrade response with error.

        :param status: int status code or http.HTTPStatus enum value
        :param body: optional bytes-like response body
        :param extra_headers: optional additional headers
        :return: a new WSUpgradeResponse object
        """
        if status < 400:
            raise ValueError(
                f"invalid error response code {status}, can be only >=400")

        self = WSUpgradeResponse()
        self.version = b"HTTP/1.1"
        self.status = HTTPStatus(status)
        self.headers = CIMultiDict()
        add_extra_headers(self.headers, extra_headers)
        self.body = body

        return self

    @staticmethod
    def create_redirect_response(status: Union[int, HTTPStatus],
                                 location: str,
                                 extra_headers: Optional[WSHeadersLike]=None):
        """
        Create upgrade response with error.

        :param status: int status code or http.HTTPStatus enum value
        :param body: optional bytes-like response body
        :param extra_headers: optional additional headers
        :return: a new WSUpgradeResponse object
        """
        if status < 300 or status > 399:
            raise ValueError(
                f"invalid redirect response code {status}, can be only 3xx")

        self = WSUpgradeResponse()
        self.version = b"HTTP/1.1"
        self.status = HTTPStatus(status)
        self.headers = CIMultiDict()
        add_extra_headers(self.headers, extra_headers)
        self.headers["Location"] = location
        self.body = None

        return self

    @staticmethod
    def create_101_response(extra_headers: Optional[WSHeadersLike]=None):
        """
        Create 101 Switching Protocols response.

        :param extra_headers: optional additional headers
        :return: a new WSUpgradeResponse object
        """
        self = WSUpgradeResponse()
        self.version = b"HTTP/1.1"
        self.status = HTTPStatus.SWITCHING_PROTOCOLS
        self.headers = CIMultiDict()
        add_extra_headers(self.headers, extra_headers)
        self.headers["Connection"] = "upgrade"
        self.headers["Upgrade"] = "websocket"
        self.body = None
        return self

    def to_bytes(self) -> bytearray:
        response_bytes = bytearray()
        response_bytes += b"%b %d %b\r\n" % (self.version, self.status.value, self.status.phrase.encode())

        if self.body:
            if "Content-Type" not in self.headers:
                self.headers.add("Content-Type", "text/plain")
            self.headers.add("Content-Length", f"{len(self.body):d}")

        for k, v in self.headers.items():
            response_bytes += f"{k}: {v}\r\n".encode()

        response_bytes += b"\r\n"
        if self.body:
            response_bytes += self.body

        return response_bytes


class WSUpgradeResponseWithListener:
    __slots__ = ("response", "listener")

    def __init__(self, response: WSUpgradeResponse, listener):
        if response.status == 101 and listener is None:
            raise ValueError(f"listener cannot be None for 101 Switching Protocols response")

        if response.status >= 400 and listener is not None:
            raise ValueError(f"listener must be None for error response")

        self.response = response
        self.listener = listener


class WSError(RuntimeError):
    """
    Thrown by :any:`ws_connect` on any kind of handshake errors.
    """
    raw_header: Optional[bytes]
    raw_body: Optional[bytes]
    response: Optional[WSUpgradeResponse]

    def __init__(self, description,
                 raw_header: Optional[bytes]=None,
                 raw_body: Optional[bytes]=None,
                 response: Optional[WSUpgradeResponse]=None):
        super().__init__(description)
        self.raw_header = raw_header
        self.raw_body = raw_body
        self.response = response


class _WSParserError(RuntimeError):
    """
    WebSocket protocol parser error.

    Used internally by the parser to notify what kind of close code we should
    send before disconnect.
    """

    def __init__(self, code, message):
        self.code = code
        super().__init__(code, message)

    def __str__(self) -> str:
        return cast(str, self.args[1])

