from __future__ import annotations

from typing import Optional, Sequence

from ..compat import Response
from ..exceptions import InvalidHandshake
from ..typing import Subprotocol
from .connection import _PerMessageDeflate


def resolve_subprotocol(
    subprotocols: Optional[Sequence[Subprotocol]],
    response: Response,
) -> Optional[Subprotocol]:
    value = response.headers.get("Sec-WebSocket-Protocol")
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidHandshake("server returned non-string subprotocol")
    if subprotocols is not None and value not in subprotocols:
        raise InvalidHandshake(f"unsupported subprotocol negotiated by server: {value}")
    return value


def configure_permessage_deflate(
    response: Response,
    compression: Optional[str],
) -> Optional[_PerMessageDeflate]:
    header_value = response.headers.get("Sec-WebSocket-Extensions")
    if header_value is None:
        return None
    if compression != "deflate":
        raise InvalidHandshake("unexpected websocket extensions negotiated by server")
    if not isinstance(header_value, str):
        raise InvalidHandshake("invalid Sec-WebSocket-Extensions header")
    return _PerMessageDeflate.from_response_header(header_value)
