from __future__ import annotations

import sys
from logging import getLogger

from picows.version import __version__

from ..typing import LoggerLike, LoggerProtocol, MaxQueue, MaxSize


def default_user_agent() -> str:
    return f"Python/{sys.version_info.major}.{sys.version_info.minor} picows-websockets/{__version__}"


default_server_header = default_user_agent


def normalize_max_size(max_size: MaxSize) -> tuple[int | None, int]:
    if isinstance(max_size, tuple):
        max_message_size, max_frame_size = max_size
    else:
        max_message_size = max_size
        max_frame_size = max_size

    return max_message_size, 2 ** 31 - 1 if max_frame_size is None else max_frame_size


def normalize_watermarks(max_queue: MaxQueue) -> tuple[int, int]:
    if max_queue is None:
        return 0, 0
    if isinstance(max_queue, tuple):
        high, low = max_queue
        if high is None:
            return 0, 0
        return high, high // 4 if low is None else low
    return max_queue, max_queue // 4


def resolve_logger(logger: LoggerLike, default_name: str) -> LoggerProtocol:
    if logger is None:
        return getLogger(default_name)
    if isinstance(logger, str):
        return getLogger(logger)
    return logger
