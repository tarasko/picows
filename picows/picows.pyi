import asyncio
from enum import Enum
from typing import Optional

from .types import (WSUpgradeRequest, WSUpgradeResponse, WSBuffer)


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
    def rsv2(self) -> bool: ...

    @property
    def rsv3(self) -> bool: ...

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
    def is_close_frame_sent(self) -> bool: ...

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
