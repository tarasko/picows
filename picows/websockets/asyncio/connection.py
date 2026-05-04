from __future__ import annotations

import asyncio
import logging
import os
import uuid
import zlib
from collections import deque
from collections.abc import AsyncIterable, Generator, Iterable
from enum import IntEnum
from time import monotonic
from typing import Any, AsyncIterator, Awaitable, Optional, Sequence, \
    Union, Dict, Tuple, Iterator, Mapping

import cython

if cython.compiled:
    from cython.cimports.picows.picows import WSListener, WSTransport, WSFrame, \
        WSMsgType, WSCloseCode
else:
    from picows import WSListener, WSTransport, WSFrame, WSMsgType, WSCloseCode

from ..compat import CloseCode, Request, Response
from ..exceptions import (
    ConcurrencyError,
    ConnectionClosed,
    ConnectionClosedError,
    ConnectionClosedOK,
    InvalidHandshake,
    InvalidStatus,
)
from ..typing import BytesLike, Data, DataLike, LoggerLike, Subprotocol


OK_CLOSE_CODES = {0, 1000, 1001}
_EMPTY_UNCOMPRESSED_BLOCK = b"\x00\x00\xff\xff"


class State(IntEnum):
    CONNECTING = 0
    OPEN = 1
    CLOSING = 2
    CLOSED = 3


@cython.cclass
class _BufferedFrame:
    msg_type: WSMsgType
    payload: bytes
    fin: bool

    def __init__(self, msg_type: WSMsgType, payload: bytes, fin: bool):
        self.msg_type = msg_type
        self.payload = payload
        self.fin = fin


class _CompressionError(Exception):
    pass


@cython.cclass
class _PerMessageDeflate:
    remote_no_context_takeover: cython.bint
    local_no_context_takeover: cython.bint
    remote_max_window_bits: cython.int
    local_max_window_bits: cython.int
    _decoder: Any
    _encoder: Any
    _decode_cont_data: cython.int

    def __init__(
        self,
        *,
        remote_no_context_takeover: bool,
        local_no_context_takeover: bool,
        remote_max_window_bits: int,
        local_max_window_bits: int,
    ):
        self.remote_no_context_takeover = remote_no_context_takeover
        self.local_no_context_takeover = local_no_context_takeover
        self.remote_max_window_bits = remote_max_window_bits
        self.local_max_window_bits = local_max_window_bits
        self._decoder = None
        self._encoder = None
        self._decode_cont_data = False

        # wbits: +9 to +15
        # The base-two logarithm of the window size, which therefore ranges between 512 and 32768.
        # Larger values produce better compression at the expense of greater memory usage.
        # The resulting output will include a zlib-specific header and trailer.
        # Negative wbits:
        # Uses the absolute value of wbits as the window size logarithm,
        # while producing a raw output stream with no header or trailing checksum.

        if not self.remote_no_context_takeover:
            self._decoder = zlib.decompressobj(wbits=-self.remote_max_window_bits)
        if not self.local_no_context_takeover:
            self._encoder = zlib.compressobj(wbits=-self.local_max_window_bits)

    @classmethod
    def from_response_header(cls, header_value: str) -> _PerMessageDeflate:
        extensions = [item.strip() for item in header_value.split(",") if item.strip()]
        if len(extensions) != 1:
            raise _CompressionError("unsupported websocket extension negotiation")

        parts = [item.strip() for item in extensions[0].split(";")]
        if not parts or parts[0] != "permessage-deflate":
            raise _CompressionError("unsupported websocket extension negotiation")

        server_no_context_takeover = False
        client_no_context_takeover = False
        server_max_window_bits = None
        client_max_window_bits = None
        seen = set()

        for raw_param in parts[1:]:
            if not raw_param:
                continue
            if "=" in raw_param:
                name, value = raw_param.split("=", 1)
                name = name.strip()
                value = value.strip()
            else:
                name = raw_param
                value = None

            if name in seen:
                raise _CompressionError(f"duplicate extension parameter: {name}")
            seen.add(name)

            if name == "server_no_context_takeover":
                if value is not None:
                    raise _CompressionError("invalid server_no_context_takeover value")
                server_no_context_takeover = True
            elif name == "client_no_context_takeover":
                if value is not None:
                    raise _CompressionError("invalid client_no_context_takeover value")
                client_no_context_takeover = True
            elif name == "server_max_window_bits":
                if value is None or not value.isdigit():
                    raise _CompressionError("invalid server_max_window_bits value")
                server_max_window_bits = int(value)
                if not 8 <= server_max_window_bits <= 15:
                    raise _CompressionError("invalid server_max_window_bits value")
            elif name == "client_max_window_bits":
                if value is None or not value.isdigit():
                    raise _CompressionError("invalid client_max_window_bits value")
                client_max_window_bits = int(value)
                if not 8 <= client_max_window_bits <= 15:
                    raise _CompressionError("invalid client_max_window_bits value")
            else:
                raise _CompressionError(f"unsupported extension parameter: {name}")

        return cls(
            remote_no_context_takeover=server_no_context_takeover,
            local_no_context_takeover=client_no_context_takeover,
            remote_max_window_bits=server_max_window_bits or 15,
            local_max_window_bits=client_max_window_bits or 15,
        )

    @cython.cfunc
    @cython.inline
    def decode_frame(self, frame: WSFrame, max_length: cython.Py_ssize_t) -> bytes:
        data: bytes
        data2: bytes

        if frame.msg_type == WSMsgType.CONTINUATION:
            if frame.rsv1:
                raise _CompressionError("unexpected rsv1 on continuation frame")
            if not self._decode_cont_data:
                return frame.get_payload_as_bytes()
            if frame.fin:
                self._decode_cont_data = False
        else:
            if not frame.rsv1:
                return frame.get_payload_as_bytes()
            if not frame.fin:
                self._decode_cont_data = True
            if self.remote_no_context_takeover or self._decoder is None:
                self._decoder = zlib.decompressobj(wbits=-self.remote_max_window_bits)

        assert self._decoder is not None
        try:
            data = self._decoder.decompress(frame.get_payload_as_memoryview(), max_length)

            if self._decoder.unconsumed_tail:
                raise _CompressionError("message too big")

            if frame.fin:
                data2 = self._decoder.decompress(_EMPTY_UNCOMPRESSED_BLOCK, max_length)
                if data2:
                    data += data2
        except zlib.error as exc:
            raise _CompressionError("decompression failed") from exc

        if frame.fin and self.remote_no_context_takeover:
            self._decoder = None

        return data

    @cython.cfunc
    @cython.inline
    def encode_frame(self, msg_type: WSMsgType, payload: BytesLike, fin: cython.bint) -> tuple[BytesLike, cython.bint]:
        if msg_type != WSMsgType.CONTINUATION and (self.local_no_context_takeover or self._encoder is None):
            self._encoder = zlib.compressobj(wbits=-self.local_max_window_bits)

        data: BytesLike = (self._encoder.compress(payload) +
                           self._encoder.flush(zlib.Z_SYNC_FLUSH))
        if fin:
            data_mv = memoryview(data)
            assert data_mv[-4:] == _EMPTY_UNCOMPRESSED_BLOCK
            data = data_mv[:-4]
            if self.local_no_context_takeover:
                self._encoder = None

        return data, msg_type != WSMsgType.CONTINUATION


@cython.cfunc
@cython.inline
def _coerce_close_code(code: CloseCode) -> Optional[int]:
    return None if code is None else code  # type: ignore[return-value]


@cython.cfunc
@cython.inline
def _coerce_close_reason(reason: Optional[str]) -> Optional[str]:
    return reason if reason is not None else None


@cython.cfunc
@cython.inline
def _resolve_subprotocol(
    subprotocols: Optional[Sequence[Subprotocol]],
    response: Any,
) -> Optional[Subprotocol]:
    if response is None:
        return None
    value = response.headers.get("Sec-WebSocket-Protocol")
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidHandshake("server returned non-string subprotocol")
    if subprotocols is not None and value not in subprotocols:
        raise InvalidHandshake(f"unsupported subprotocol negotiated by server: {value}")
    return value


@cython.cfunc
@cython.inline
def _normalize_watermarks(
    max_queue: Union[int, tuple[Optional[int], Optional[int]], None],
) -> tuple[cython.Py_ssize_t, cython.Py_ssize_t]:
    if max_queue is None:
        return 0, 0
    if isinstance(max_queue, tuple):
        high, low = max_queue
        if high is None:
            return 0, 0
        return high, high // 4 if low is None else low
    return max_queue, max_queue // 4


@cython.cfunc
@cython.inline
def _resolve_logger(logger: LoggerLike) -> Union[logging.Logger, logging.LoggerAdapter[Any]]:
    if logger is None:
        return logging.getLogger("websockets.client")
    if isinstance(logger, str):
        return logging.getLogger(logger)
    return logger


@cython.ccall
def process_exception(exc: Exception) -> Optional[Exception]:
    if isinstance(exc, (EOFError, OSError, asyncio.TimeoutError)):
        return None
    if isinstance(exc, InvalidStatus):
        status = exc.response.status
        if int(status) in {500, 502, 503, 504}:
            return None
    return exc


@cython.cclass
class ClientConnection(WSListener):  # type: ignore[misc]
    id: uuid.UUID
    logger: Union[logging.Logger, logging.LoggerAdapter[Any]]
    transport: WSTransport
    _request: Request
    _response: Response
    _connect_exception: Optional[Exception]
    _subprotocols: Optional[Sequence[Subprotocol]]
    _subprotocol: Optional[Subprotocol]
    _compression: Optional[str]
    _permessage_deflate: Optional[_PerMessageDeflate]
    _state: State
    _close_exc: Optional[ConnectionClosed]
    _loop: asyncio.AbstractEventLoop

    # Send side
    _send_in_progress: cython.bint
    _send_waiters: deque[asyncio.Future[None]]
    _write_ready: Optional[asyncio.Future[None]]
    _write_limit: Union[int, tuple[int, Optional[int]]]

    # Recv side
    _recv_in_progress: cython.bint
    _recv_streaming_broken: cython.bint
    _paused_reading: cython.bint
    _recv_waiter: Optional[asyncio.Future[None]]
    _recv_queue: deque[Optional[_BufferedFrame]]
    _max_message_size: cython.Py_ssize_t
    _max_queue_high: cython.Py_ssize_t
    _max_queue_low: cython.Py_ssize_t
    _incoming_message_active: cython.bint
    _incoming_message_size: cython.Py_ssize_t

    _pending_pings: Dict[bytes, Tuple[asyncio.Future[float], float]]
    _ping_interval: Optional[float]
    _ping_timeout: Optional[float]
    _close_timeout: Optional[float]
    _keepalive_task: Optional[asyncio.Task[None]]
    _latency: cython.double

    def __init__(
        self,
        *,
        ping_interval: Optional[float] = 20,
        ping_timeout: Optional[float] = 20,
        close_timeout: Optional[float] = 10,
        max_queue: Union[int, tuple[Optional[int], Optional[int]], None] = 16,
        write_limit: Union[int, tuple[int, Optional[int]]] = 32768,
        max_message_size: Optional[int] = 1024 * 1024,
        logger: LoggerLike = None,
        subprotocols: Optional[Sequence[Subprotocol]] = None,
        compression: Optional[str] = None,
    ):
        self.id = uuid.uuid4()
        self.logger = _resolve_logger(logger)
        self.transport = cython.cast(WSTransport, None)
        self._request = None  # type: ignore[assignment]
        self._response = None  # type: ignore[assignment]
        self._connect_exception = None
        self._subprotocols = subprotocols
        self._subprotocol = None
        self._compression = compression
        self._permessage_deflate = None
        self._state = State.CONNECTING
        self._close_exc: Optional[ConnectionClosed] = None
        self._loop = asyncio.get_running_loop()

        self._send_in_progress = False
        self._send_waiters = deque()
        self._write_ready: Optional[asyncio.Future[None]] = None
        self._write_limit = write_limit

        self._recv_in_progress = False
        self._recv_streaming_broken = False
        self._paused_reading = False
        self._recv_waiter = None
        self._recv_queue = deque()
        self._max_message_size = 0 if max_message_size is None else max_message_size
        self._max_queue_high, self._max_queue_low = _normalize_watermarks(max_queue)
        self._incoming_message_active = False
        self._incoming_message_size = 0

        self._pending_pings: dict[bytes, tuple[asyncio.Future[float], float]] = {}
        self._ping_interval = ping_interval
        self._ping_timeout = ping_timeout
        self._close_timeout = close_timeout
        self._keepalive_task: Optional[asyncio.Task[None]] = None
        self._latency = 0.0

    @cython.ccall
    def on_ws_connected(self, transport: WSTransport) -> None:
        self.transport = transport
        self._request = transport.request
        self._response = transport.response
        try:
            self._subprotocol = _resolve_subprotocol(self._subprotocols, self._response)
            self._configure_extensions()
        except InvalidHandshake as exc:
            self._connect_exception = exc
            self.transport.send_close(WSCloseCode.PROTOCOL_ERROR, str(exc).encode("utf-8"))
            self.transport.disconnect(False)
            return
        self._state = State.OPEN
        self._set_write_limits(self._write_limit)
        if self._ping_interval is not None and self._keepalive_task is None:
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    @cython.ccall
    def on_ws_disconnected(self, transport: WSTransport) -> None:
        self._state = State.CLOSED
        self._set_close_exception()
        self._add_to_recv_queue(None)
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            self._keepalive_task = None
        if self._write_ready is not None:
            if not self._write_ready.done():
                self._write_ready.set_exception(
                    self._close_exc or ConnectionClosedError(None, None, None)
                )
            self._write_ready = None
        for waiter, _ in self._pending_pings.values():
            if not waiter.done():
                waiter.set_exception(self._close_exc or ConnectionClosedError(None, None, None))
        self._pending_pings.clear()

    @cython.cfunc
    @cython.inline
    def _process_pong_frame(self, frame: WSFrame) -> None:
        ping = self._pending_pings.pop(frame.get_payload_as_bytes(), None)
        if ping is not None:
            waiter, sent_at = ping
            self._latency = monotonic() - sent_at
            if not waiter.done():
                waiter.set_result(self._latency)

    @cython.cfunc
    @cython.inline
    def _process_close_frame(self, frame: WSFrame) -> None:
        close_code = frame.get_close_code()
        close_message = frame.get_close_message()
        self.transport.send_close(close_code, close_message)
        self.transport.disconnect()
        self._state = State.CLOSING

    @cython.ccall
    def on_ws_frame(self, transport: WSTransport, frame: WSFrame) -> None:
        if frame.msg_type == WSMsgType.PONG:
            self._process_pong_frame(frame)
            return

        if frame.msg_type == WSMsgType.CLOSE:
            self._process_close_frame(frame)
            return

        if frame.msg_type not in (WSMsgType.TEXT, WSMsgType.BINARY, WSMsgType.CONTINUATION):
            self._fail_protocol_error("unsupported frame opcode")
            return

        if self._permessage_deflate is None and frame.rsv1:
            self._fail_protocol_error("received compressed frame without negotiated permessage-deflate")
            return

        if frame.msg_type == WSMsgType.CONTINUATION and not self._incoming_message_active:
            self._fail_protocol_error("unexpected continuation frame")
            return

        if frame.msg_type != WSMsgType.CONTINUATION and self._incoming_message_active:
            self._fail_protocol_error("expected continuation frame")
            return

        payload: bytes
        if self._permessage_deflate is not None:
            remaining = 0 if self._max_message_size == 0 else (
                max(self._max_message_size - self._incoming_message_size, 0))
            try:
                payload = self._permessage_deflate.decode_frame(frame, remaining)
            except _CompressionError as exc:
                if str(exc) == "message too big":
                    self._fail_message_too_big("message too big")
                else:
                    self._fail_protocol_error(str(exc))
                return
        else:
            payload = frame.get_payload_as_bytes()

        self._incoming_message_size = len(payload)
        if self._max_message_size > 0 and self._incoming_message_size > self._max_message_size:
            self._fail_message_too_big("message too big")
            return

        if frame.msg_type == WSMsgType.CONTINUATION:
            if frame.fin:
                self._incoming_message_active = False
                self._incoming_message_size = 0
        else:
            if frame.fin:
                self._incoming_message_size = 0
            else:
                self._incoming_message_active = True

        self._add_to_recv_queue(_BufferedFrame(frame.msg_type, payload, frame.fin))
        self._pause_reading_if_needed()

    @cython.ccall
    def pause_writing(self) -> None:
        if self._write_ready is None:
            self._write_ready = self._loop.create_future()

    @cython.ccall
    def resume_writing(self) -> None:
        if self._write_ready is not None:
            if not self._write_ready.done():
                self._write_ready.set_result(None)
            self._write_ready = None

    @cython.cfunc
    @cython.inline
    def _set_write_limits(self, write_limit: Union[int, tuple[int, Optional[int]]]) -> None:
        if isinstance(write_limit, tuple):
            high, low = write_limit
        else:
            high, low = write_limit, None
        self.transport.underlying_transport.set_write_buffer_limits(high=high, low=low)

    @cython.cfunc
    @cython.inline
    def _pause_reading_if_needed(self) -> None:
        if self._max_queue_high > 0 and not self._paused_reading and len(self._recv_queue) >= self._max_queue_high:
            self.transport.underlying_transport.pause_reading()
            self._paused_reading = True

    @cython.cfunc
    @cython.inline
    def _resume_reading_if_needed(self) -> None:
        if not self._paused_reading:
            return
        if self._max_queue_low == 0 or len(self._recv_queue) <= self._max_queue_low:
            self.transport.underlying_transport.resume_reading()
            self._paused_reading = False

    @cython.cfunc
    @cython.inline
    def _add_to_recv_queue(self, frame: Optional[_BufferedFrame]) -> None:
        self._recv_queue.append(frame)
        waiter = self._recv_waiter
        if waiter is not None:
            self._recv_waiter = None
            if not waiter.done():
                waiter.set_result(None)

    @cython.cfunc
    @cython.inline
    def _wait_recv_queue_not_empty(self) -> asyncio.Future[None]:
        assert self._recv_waiter is None
        waiter: asyncio.Future[None] = self._loop.create_future()
        self._recv_waiter = waiter
        return waiter

    @cython.cfunc
    @cython.inline
    def _configure_extensions(self) -> None:
        header_value = self._response.headers.get("Sec-WebSocket-Extensions")
        if header_value is None:
            return
        if self._compression != "deflate":
            raise InvalidHandshake("unexpected websocket extensions negotiated by server")
        if not isinstance(header_value, str):
            raise InvalidHandshake("invalid Sec-WebSocket-Extensions header")
        try:
            self._permessage_deflate = _PerMessageDeflate.from_response_header(header_value)
        except _CompressionError as exc:
            raise InvalidHandshake(str(exc)) from exc

    @cython.cfunc
    @cython.inline
    def _set_close_exception(self) -> None:
        handshake = self.transport.close_handshake
        if handshake is None:
            self._close_exc = ConnectionClosedError(None, None, None)
            return
        rcvd = handshake.recv
        sent = handshake.sent
        rcvd_then_sent = handshake.recv_then_sent
        rcvd_code = _coerce_close_code(rcvd.code) if rcvd is not None else None
        sent_code = _coerce_close_code(sent.code) if sent is not None else None
        ok = (
            (rcvd_code in OK_CLOSE_CODES or rcvd_code is None)
            and (sent_code in OK_CLOSE_CODES or sent_code is None)
        )
        exc_type = ConnectionClosedOK if ok else ConnectionClosedError
        self._close_exc = exc_type(rcvd, sent, rcvd_then_sent)

    @cython.cfunc
    @cython.inline
    def _connection_closed(self) -> ConnectionClosed:
        if self._close_exc is None:
            self._set_close_exception()
        return self._close_exc or ConnectionClosedError(None, None, None)

    @cython.cfunc
    @cython.inline
    def _fail_protocol_error(self, message: str) -> None:
        self.transport.send_close(WSCloseCode.PROTOCOL_ERROR, message.encode("utf-8"))
        self.transport.disconnect(False)

    @cython.cfunc
    @cython.inline
    def _fail_message_too_big(self, message: str) -> None:
        self.transport.send_close(WSCloseCode.MESSAGE_TOO_BIG, message.encode("utf-8"))
        self.transport.disconnect(False)

    @cython.cfunc
    @cython.inline
    def _set_recv_in_progress(self) -> None:
        if self._recv_in_progress:
            raise ConcurrencyError("cannot call recv() or recv_streaming() concurrently")
        if self._recv_streaming_broken:
            raise ConcurrencyError("recv_streaming() wasn't fully consumed")
        self._recv_in_progress = True

    async def _wait_send_turn(self) -> None:
        waiter: asyncio.Future[None] = self._loop.create_future()
        self._send_waiters.append(waiter)
        try:
            await waiter
        except Exception:
            try:
                self._send_waiters.remove(waiter)
            except ValueError:
                pass
            raise

    @cython.cfunc
    @cython.inline
    def _release_send(self) -> None:
        waiter: asyncio.Future[None]

        while self._send_waiters:
            waiter = self._send_waiters.popleft()
            if not waiter.done():
                waiter.set_result(None)
                return

        self._send_in_progress = False

    @cython.cfunc
    @cython.inline
    def _decode_data(self, payload: bytes, msg_type: WSMsgType, decode: Optional[bool]) -> Data:
        if decode is True or (msg_type == WSMsgType.TEXT and decode is None):
            return payload.decode("utf-8")
        else:
            return payload

    @cython.cfunc
    @cython.inline
    def _check_frame(self, frame: Optional[_BufferedFrame]) -> _BufferedFrame:
        self._resume_reading_if_needed()
        if frame is None:
            raise self._connection_closed()
        return frame

    async def recv(self, decode: Optional[bool] = None) -> Data:
        frame: _BufferedFrame

        self._set_recv_in_progress()

        try:
            if not self._recv_queue:
                await self._wait_recv_queue_not_empty()
            frame = self._check_frame(self._recv_queue.popleft())

            msg_type = frame.msg_type
            if frame.fin:
                return self._decode_data(frame.payload, msg_type, decode) # type: ignore[no-any-return]

            frames = [frame]
            try:
                payloads = [frame.payload]
                while not frame.fin:
                    if not self._recv_queue:
                        await self._wait_recv_queue_not_empty()
                    frame = self._check_frame(self._recv_queue.popleft())

                    frames.append(frame)
                    payloads.append(frame.payload)

                payload = b"".join(payloads)
                return self._decode_data(payload, msg_type, decode)
            except asyncio.CancelledError:
                self._recv_queue.extendleft(reversed(frames))
                raise
        finally:
            self._recv_in_progress = False
            self._recv_waiter = None

    def recv_streaming(self, decode: Optional[bool] = None) -> AsyncIterator[Data]:
        self._set_recv_in_progress()

        msg_started: cython.bint = False
        msg_finished: cython.bint = False
        frame: _BufferedFrame
        msg_type: WSMsgType

        async def iterator() -> AsyncIterator[Data]:
            nonlocal msg_started, msg_finished

            try:
                if not self._recv_queue:
                    await self._wait_recv_queue_not_empty()
                frame = self._check_frame(self._recv_queue.popleft())

                msg_started = True
                msg_type = frame.msg_type
                yield self._decode_data(frame.payload, msg_type, decode)

                while not frame.fin:
                    if not self._recv_queue:
                        await self._wait_recv_queue_not_empty()
                    frame = self._check_frame(self._recv_queue.popleft())

                    yield self._decode_data(frame.payload, msg_type, decode)
                msg_finished = True
            finally:
                self._recv_in_progress = False
                self._recv_waiter = None
                if msg_started and not msg_finished:
                    self._recv_streaming_broken = True
                elif msg_finished:
                    self._recv_streaming_broken = False

        return iterator()

    def _encode_and_send(self, msg_type: WSMsgType, message: Data, fin: cython.bint) -> None:
        rsv1: cython.bint = False
        if self._permessage_deflate is not None:
            message, rsv1 = self._permessage_deflate.encode_frame(
                msg_type, self._compression_payload(message), fin
            )

        self.transport.send(msg_type, message, fin, rsv1)

    async def send(
        self,
        message: Union[DataLike, Iterable[DataLike], AsyncIterator[DataLike]],
        text: Optional[bool] = None,
    ) -> None:
        # Catch a common mistake -- passing a dict to send().
        if isinstance(message, Mapping):
            raise TypeError("data is a dict-like object")

        if self._state is State.CLOSED:
            raise self._connection_closed()

        if self._send_in_progress:
            await self._wait_send_turn()
        else:
            self._send_in_progress = True

        try:
            if isinstance(message, (str, bytes, bytearray, memoryview)):
                if isinstance(message, str):
                    msg_type = WSMsgType.BINARY if text is False else WSMsgType.TEXT
                else:
                    msg_type = WSMsgType.TEXT if text else WSMsgType.BINARY

                self._encode_and_send(msg_type, message, True)

                if self._write_ready is not None:
                    await self._write_ready
            elif isinstance(message, (AsyncIterable, Iterable)):
                await self._send_fragments(message, text)  # type: ignore[arg-type]
            else:
                raise TypeError(f"message has unsupported type {type(message).__name__}")
        finally:
            self._release_send()

    @cython.cfunc
    @cython.inline
    def _check_fragment_type(self, message: DataLike, first_is_str: cython.bint) -> None:
        if first_is_str and isinstance(message, str):
            return
        elif not first_is_str and isinstance(message, (bytes, bytearray, memoryview)):
            return

        raise TypeError("all fragments must be of the same category: str vs bytes-like")

    @cython.cfunc
    @cython.inline
    def _compression_payload(self, message: DataLike) -> BytesLike:
        if isinstance(message, str):
            return message.encode("utf-8")
        return message

    async def _send_fragments(
        self,
        messages: Union[AsyncIterable[DataLike], Iterable[DataLike]],
        text: Optional[bool],
    ) -> None:
        is_async: cython.bint
        async_iterator: AsyncIterator[DataLike]
        iterator: Iterator[DataLike]
        stop_exception_type: Union[type[StopAsyncIteration], type[StopIteration]]

        if isinstance(messages, AsyncIterable):
            async_iterator = messages.__aiter__()
            iterator = None # type: ignore[assignment]
            stop_exception_type = StopAsyncIteration
            is_async = True
        else:
            async_iterator = None # type: ignore[assignment]
            iterator = iter(messages)
            stop_exception_type = StopIteration
            is_async = False

        try:
            try:
                if is_async:
                    current = await anext(async_iterator)
                else:
                    current = next(iterator)
            except stop_exception_type:
                raise TypeError("message iterable cannot be empty") from None

            first_is_str: cython.bint
            if isinstance(current, str):
                msg_type = WSMsgType.BINARY if text is False else WSMsgType.TEXT
                first_is_str = True
            elif isinstance(current, (bytes, bytearray, memoryview)):
                msg_type = WSMsgType.TEXT if text else WSMsgType.BINARY
                first_is_str = False
            else:
                raise TypeError(f"message must contain str or bytes-like objects, got {type(current).__name__}")

            while True:
                # Original websockets implementations always send one last empty
                # frame with fin=True even if iterator returns only one fragment
                # Perhaps this is useful for the users, just replicate this
                # behavior.
                self._encode_and_send(msg_type, current, False)
                msg_type = WSMsgType.CONTINUATION

                try:
                    if is_async:
                        current = await anext(async_iterator)
                    else:
                        current = next(iterator)
                except stop_exception_type:
                    break

                self._check_fragment_type(current, first_is_str)
                if self._write_ready is not None:
                    await self._write_ready

            # Send the last empty frame with fin=True
            self._encode_and_send(msg_type, b"", True)
            if self._write_ready is not None:
                await self._write_ready
        except Exception:
            self._fail_protocol_error("error in fragmented message")
            raise

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self._state is State.CLOSED:
            return
        if self._state is State.OPEN:
            self._state = State.CLOSING
        self.transport.send_close(code, reason.encode("utf-8"))
        try:
            if self._close_timeout is None:
                await self.wait_closed()
            else:
                await asyncio.wait_for(self.wait_closed(), self._close_timeout)
        except asyncio.TimeoutError:
            self.transport.disconnect(False)
            await self.wait_closed()

    async def wait_closed(self) -> None:
        await self.transport.wait_disconnected()

    async def ping(self, data: Optional[Union[str, bytes]] = None) -> Awaitable[float]:
        if self._state is State.CLOSED:
            raise self._connection_closed()
        if data is None:
            while True:
                payload = os.urandom(4)
                if payload not in self._pending_pings:
                    break
        elif isinstance(data, str):
            payload = data.encode("utf-8")
        elif isinstance(data, bytes):
            payload = data
        else:
            raise TypeError("ping payload must be str, bytes, or None")

        if payload in self._pending_pings:
            raise ConcurrencyError("another ping was sent with the same data")

        waiter: asyncio.Future[float] = asyncio.get_running_loop().create_future()
        self._pending_pings[payload] = (waiter, monotonic())
        self.transport.send_ping(payload)
        return waiter

    async def pong(self, data: Union[str, bytes] = b"") -> None:
        if self._state is State.CLOSED:
            raise self._connection_closed()
        self.transport.send_pong(data)

    async def _keepalive_loop(self) -> None:
        try:
            while True:
                assert self._ping_interval is not None
                await asyncio.sleep(self._ping_interval)
                waiter = await self.ping()
                if self._ping_timeout is None:
                    continue
                await asyncio.wait_for(waiter, self._ping_timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            if self.state is not State.CLOSED:
                await self.close(code=1011, reason="keepalive ping timeout")

    async def __aenter__(self): # type: ignore[no-untyped-def]
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    def __aiter__(self) -> AsyncIterator[Union[str, bytes]]:
        return self._iterate_messages()

    async def _iterate_messages(self) -> AsyncIterator[Data]:
        while True:
            try:
                yield await self.recv()
            except ConnectionClosedOK:
                return

    @property
    def state(self) -> State:
        return self._state

    @property
    def request(self) -> Request:
        return self._request

    @property
    def response(self) -> Response:
        return self._response

    @property
    def connect_exception(self) -> Optional[Exception]:
        return self._connect_exception

    @property
    def local_address(self) -> Any:
        return self.transport.underlying_transport.get_extra_info("sockname")

    @property
    def remote_address(self) -> Any:
        return self.transport.underlying_transport.get_extra_info("peername")

    @property
    def latency(self) -> float:
        return self._latency    # type: ignore[no-any-return]

    @property
    def subprotocol(self) -> Optional[Subprotocol]:
        return self._subprotocol

    @property
    def close_code(self) -> Optional[int]:
        handshake = self.transport.close_handshake
        if handshake is None:
            return None
        if handshake.recv is not None:
            return _coerce_close_code(handshake.recv.code)  # type: ignore[no-any-return]
        if handshake.sent is not None:
            return _coerce_close_code(handshake.sent.code)  # type: ignore[no-any-return]
        return None

    @property
    def close_reason(self) -> Optional[str]:
        handshake = self.transport.close_handshake
        if handshake is None:
            return None
        if handshake.recv is not None:
            return _coerce_close_reason(handshake.recv.reason)  # type: ignore[no-any-return]
        if handshake.sent is not None:
            return _coerce_close_reason(handshake.sent.reason)  # type: ignore[no-any-return]
        return None
