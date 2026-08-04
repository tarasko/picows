from __future__ import annotations

from typing import Any


def route(*args: Any, **kwargs: Any) -> Any:
    raise NotImplementedError("route() requires unsupported server process_request hooks")
