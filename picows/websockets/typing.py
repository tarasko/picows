from __future__ import annotations

import logging
from http import HTTPStatus
from typing import Any

from picows.types import WSHeadersLike

BytesLike = bytes | bytearray | memoryview
Data = str | bytes
DataLike = str | bytes | bytearray | memoryview
HeadersLike = WSHeadersLike
LoggerLike = logging.Logger | logging.LoggerAdapter[Any] | str | None
StatusLike = HTTPStatus | int
Origin = str
Subprotocol = str
ExtensionName = str
ExtensionParameter = tuple[str, str | None]

__all__ = [
    "BytesLike",
    "Data",
    "DataLike",
    "ExtensionName",
    "ExtensionParameter",
    "HeadersLike",
    "LoggerLike",
    "Origin",
    "StatusLike",
    "Subprotocol",
]
