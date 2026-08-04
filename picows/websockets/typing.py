from __future__ import annotations

from http import HTTPStatus
from typing import Any, Optional, Protocol, Tuple, Union

from picows.common import WSHeadersLike

BytesLike = Union[bytes, bytearray, memoryview]
Data = Union[str, bytes]
DataLike = Union[str, bytes, bytearray, memoryview]
HeadersLike = WSHeadersLike
MaxSize = Union[int, None, tuple[Optional[int], Optional[int]]]
MaxQueue = Union[int, None, tuple[Optional[int], Optional[int]]]


class LoggerProtocol(Protocol):
    @property
    def debug(self) -> Any:
        ...

    @property
    def info(self) -> Any:
        ...

    @property
    def warning(self) -> Any:
        ...

    @property
    def error(self) -> Any:
        ...


LoggerLike = Union[LoggerProtocol, str, None]
StatusLike = Union[HTTPStatus, int]
Origin = str
Subprotocol = str
ExtensionName = str
ExtensionParameter = Tuple[str, Optional[str]]

__all__ = [
    "BytesLike",
    "Data",
    "DataLike",
    "ExtensionName",
    "ExtensionParameter",
    "HeadersLike",
    "LoggerLike",
    "LoggerProtocol",
    "MaxQueue",
    "MaxSize",
    "Origin",
    "StatusLike",
    "Subprotocol",
]
