import asyncio
from enum import Enum
from ssl import SSLContext
from collections.abc import Callable, Iterable
from typing import Final

PICOWS_DEBUG_LL: Final = 9

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
    def get_payload_as_bytes(self) -> bytes: ...
    def get_payload_as_utf8_text(self) -> str: ...
    def get_payload_as_ascii_text(self) -> str: ...
    def get_payload_as_memoryview(self) -> object: ...
    def get_close_code(self) -> WSCloseCode: ...
    def get_close_message(self) -> bytes: ...
    def __str__(self): ...

class WSTransport:
    def __init__(self, is_client_side: bool, underlying_transport, logger, loop): ...
    def send(
        self,
        msg_type: WSMsgType,
        message,
        fin: bool = True,
        rsv1: bool = False,
    ): ...
    def send_ping(self, message=None): ...
    def send_pong(self, message=None): ...
    def send_close(self, close_code: WSCloseCode = ..., close_message=None): ...
    def disconnect(self, graceful: bool = True): ...
    async def wait_disconnected(self): ...
    async def measure_roundtrip_time(self, rounds: int) -> list[float]: ...
    def notify_user_specific_pong_received(self): ...

class WSListener:
    def on_ws_connected(self, transport: WSTransport): ...
    def on_ws_frame(self, transport: WSTransport, frame: WSFrame): ...
    def on_ws_disconnected(self, transport: WSTransport): ...
    def send_user_specific_ping(self, transport: WSTransport): ...
    def is_user_specific_pong(self, frame: WSFrame): ...
    def pause_writing(self): ...
    def resume_writing(self): ...

class WSUpgradeRequest: ...

async def ws_connect(
    ws_listener_factory: Callable[[], WSListener],
    url: str,
    *,
    ssl_context: SSLContext | None = None,
    disconnect_on_exception: bool = True,
    websocket_handshake_timeout=5,
    logger_name: str = "client",
    enable_auto_ping: bool = False,
    auto_ping_idle_timeout: float = 10,
    auto_ping_reply_timeout: float = 10,
    auto_ping_strategy: WSAutoPingStrategy = ...,
    enable_auto_pong: bool = True,
    **kwargs,
) -> tuple[WSTransport, WSListener]: ...
async def ws_create_server(
    ws_listener_factory: Callable[[WSUpgradeRequest], WSListener | None],
    host: str | Iterable[str] | None = None,
    port: int | None = None,
    *,
    disconnect_on_exception: bool = True,
    websocket_handshake_timeout: int = 5,
    logger_name: str = "server",
    enable_auto_ping: bool = False,
    auto_ping_idle_timeout: float = 20,
    auto_ping_reply_timeout: float = 20,
    auto_ping_strategy: WSAutoPingStrategy = ...,
    enable_auto_pong: bool = True,
    **kwargs,
) -> asyncio.Server: ...
