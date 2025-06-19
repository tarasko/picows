import asyncio
from enum import Enum
from ssl import SSLContext
from http import HTTPStatus
from collections.abc import Callable, Mapping, Iterable
from typing import Final, Optional, Any, Union
from multidict import CIMultiDict


PICOWS_DEBUG_LL: Final = 9
WSHeadersLike = Union[Mapping[str, str], Iterable[tuple[str, str]]]
WSServerListenerFactory = Callable[[WSUpgradeRequest], Union[WSListener, WSUpgradeResponseWithListener, None]]
WSBuffer = Union[bytes, bytearray, memoryview]


class WSError(RuntimeError): ...


class WSMsgType(Enum):
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    PING = 0x9
    PONG = 0xA
    CLOSE = 0x8


class WSCloseCode(Enum):
    NO_INFO = 0
    OK = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    ABNORMAL_CLOSURE = 1006
    INVALID_TEXT = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MANDATORY_EXTENSION = 1010
    INTERNAL_ERROR = 1011
    SERVICE_RESTART = 1012
    TRY_AGAIN_LATER = 1013
    BAD_GATEWAY = 1014


class WSAutoPingStrategy(Enum):
    PING_WHEN_IDLE = 1
    PING_PERIODICALLY = 2


class WSFrame:
    @property
    def tail_size(self) -> int: ...

    @property
    def msg_type(self) -> WSMsgType: ...

    @property
    def fin(self) -> bool: ...

    @property
    def rsv1(self) -> bool: ...

    @property
    def last_in_buffer(self) -> bool: ...

    def get_payload_as_bytes(self) -> bytes: ...
    def get_payload_as_utf8_text(self) -> str: ...
    def get_payload_as_ascii_text(self) -> str: ...
    def get_payload_as_memoryview(self) -> memoryview: ...
    def get_close_code(self) -> WSCloseCode: ...
    def get_close_message(self) -> bytes: ...
    def __str__(self) -> str: ...


class WSTransport:
    @property
    def underlying_transport(self) -> asyncio.Transport: ...

    @property
    def is_client_side(self) -> bool: ...

    @property
    def is_secure(self) -> bool: ...

    @property
    def request(self) -> WSUpgradeRequest: ...

    @property
    def response(self) -> WSUpgradeResponse: ...

    def send(
        self,
        msg_type: WSMsgType,
        message: Optional[WSBuffer],
        fin: bool = True,
        rsv1: bool = False,
    ) -> None: ...
    def send_reuse_external_bytearray(
        self,
        msg_type: WSMsgType,
        buffer: bytearray,
        msg_offset: int,
        fin: bool = True,
        rsv1: bool = False
    ) -> None: ...
    def send_ping(self, message: Optional[WSBuffer]=None) -> None: ...
    def send_pong(self, message: Optional[WSBuffer]=None) -> None: ...
    def send_close(self, close_code: WSCloseCode = ..., close_message: Optional[WSBuffer]=None) -> None: ...
    def disconnect(self, graceful: bool = True) -> None: ...
    async def wait_disconnected(self) -> None: ...
    async def measure_roundtrip_time(self, rounds: int) -> list[float]: ...
    def notify_user_specific_pong_received(self) -> None: ...


class WSListener:
    def on_ws_connected(self, transport: WSTransport) -> None: ...
    def on_ws_frame(self, transport: WSTransport, frame: WSFrame) -> None: ...
    def on_ws_disconnected(self, transport: WSTransport) -> None: ...
    def send_user_specific_ping(self, transport: WSTransport) -> None: ...
    def is_user_specific_pong(self, frame: WSFrame) -> bool: ...
    def pause_writing(self) -> None: ...
    def resume_writing(self) -> None: ...


class WSUpgradeRequest:
    @property
    def method(self) -> bytes: ...

    @property
    def path(self) -> bytes: ...

    @property
    def version(self) -> bytes: ...

    @property
    def headers(self) -> CIMultiDict[str]: ...


class WSUpgradeResponse:
    @staticmethod
    def create_error_response(
            status: Union[int, HTTPStatus],
            body: Optional[bytes]=None,
            extra_headers: Optional[WSHeadersLike]=None
    ) -> WSUpgradeResponse: ...

    @staticmethod
    def create_101_response(
            extra_headers: Optional[WSHeadersLike]=None
    ) -> WSUpgradeResponse: ...

    @property
    def version(self) -> bytes: ...

    @property
    def status(self) -> HTTPStatus: ...

    @property
    def headers(self) -> CIMultiDict[str]: ...


class WSUpgradeResponseWithListener:
    def __init__(self, response: WSUpgradeResponse, listener: Optional[WSListener]): ...


async def ws_connect(
    ws_listener_factory: Callable[[], WSListener],
    url: str,
    *args: Any,
    ssl_context: Union[SSLContext, None] = None,
    disconnect_on_exception: bool = True,
    websocket_handshake_timeout: float = 5,
    logger_name: str = "client",
    enable_auto_ping: bool = False,
    auto_ping_idle_timeout: float = 10,
    auto_ping_reply_timeout: float = 10,
    auto_ping_strategy: WSAutoPingStrategy = ...,
    enable_auto_pong: bool = True,
    extra_headers: Optional[WSHeadersLike] = None,
    **kwargs: Any
) -> tuple[WSTransport, WSListener]: ...

# TODO: In python 3.8 asyncio has a bug that it doesn't export Server,
# so reference it directly from asyncio.base_events.
# Soon python 3.8 support will be gone and we can annotate asyncio.Server

async def ws_create_server(
    ws_listener_factory: WSServerListenerFactory,
    host: Union[str, Iterable[str], None] = None,
    port: Union[int, None] = None,
    *args: Any,
    disconnect_on_exception: bool = True,
    websocket_handshake_timeout: float = 5,
    logger_name: str = "server",
    enable_auto_ping: bool = False,
    auto_ping_idle_timeout: float = 20,
    auto_ping_reply_timeout: float = 20,
    auto_ping_strategy: WSAutoPingStrategy = ...,
    enable_auto_pong: bool = True,
    **kwargs: Any
) -> asyncio.base_events.Server: ...
