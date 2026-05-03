from __future__ import annotations

import asyncio
import logging
import os
import uuid
from collections import deque
from collections.abc import AsyncIterable, Generator, Iterable
from enum import IntEnum
from time import monotonic
from typing import Any, AsyncIterator, Awaitable, Optional, Sequence, \
    Union, cast, Dict, Tuple, Iterator

import cython

if cython.compiled:
    from cython.cimports.picows.picows import WSListener, WSTransport, WSFrame, \
        WSMsgType, WSCloseCode
else:
    from picows import WSListener, WSTransport, WSFrame, WSMsgType, WSCloseCode


import picows

from ..compat import CloseCode, Request, Response
from ..exceptions import (
    ConcurrencyError,
    ConnectionClosed,
    ConnectionClosedError,
    ConnectionClosedOK,
    InvalidHandshake,
    InvalidStatus,
)
from ..typing import Data, DataLike, LoggerLike, Subprotocol


OK_CLOSE_CODES = {0, 1000, 1001}
_QUEUE_EMPTY = object()


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


@cython.cclass
class _SingleConsumerQueue:
    _loop: asyncio.AbstractEventLoop
    _items: deque[Optional[_BufferedFrame]]
    _waiter: Optional[asyncio.Future[Optional[_BufferedFrame]]]

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        self._items = deque()
        self._waiter = None

    @cython.cfunc
    @cython.inline
    def put(self, item: Optional[_BufferedFrame]) -> None:
        waiter = self._waiter
        if waiter is not None:
            self._waiter = None
            if not waiter.done():
                waiter.set_result(item)
                return
        self._items.append(item)

    @cython.cfunc
    @cython.inline
    def get_nowait(self) -> object:
        if self._items:
            return self._items.popleft()
        return _QUEUE_EMPTY

    async def get(self) -> Optional[_BufferedFrame]:
        item = self.get_nowait()
        if item is not _QUEUE_EMPTY:
            return cast(Optional[_BufferedFrame], item)

        waiter: asyncio.Future[Optional[_BufferedFrame]] = self._loop.create_future()
        self._waiter = waiter
        try:
            return await waiter
        except Exception:
            if self._waiter is waiter:
                self._waiter = None
            raise

    @cython.cfunc
    @cython.inline
    def qsize(self) -> cython.Py_ssize_t:
        return len(self._items)


@cython.cfunc
@cython.inline
def _coerce_close_code(code: CloseCode) -> Optional[int]:
    return None if code is None else cast(int, code)


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
    if subprotocols is not None and value not in subprotocols:
        raise InvalidHandshake(f"unsupported subprotocol negotiated by server: {value}")
    return cast(Subprotocol, value)


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
    request: Request
    response: Response
    _subprotocols: Optional[Sequence[Subprotocol]]
    _subprotocol: Optional[Subprotocol]
    _state: State
    _frames: _SingleConsumerQueue
    _close_exc: Optional[ConnectionClosed]
    _loop: asyncio.AbstractEventLoop
    _recv_in_progress: cython.bint
    _send_in_progress: cython.bint
    _send_waiters: deque[asyncio.Future[None]]
    _write_ready: Optional[asyncio.Future[None]]
    _recv_streaming_broken: cython.bint
    _pending_pings: Dict[bytes, Tuple[asyncio.Future[float], float]]
    _ping_interval: Optional[float]
    _ping_timeout: Optional[float]
    _close_timeout: Optional[float]
    _keepalive_task: Optional[asyncio.Task[None]]
    _latency: cython.double
    _max_message_size: cython.Py_ssize_t
    _max_queue_high: cython.Py_ssize_t
    _max_queue_low: cython.Py_ssize_t
    _incoming_message_active: cython.bint
    _incoming_message_size: cython.Py_ssize_t
    _write_limit: Union[int, tuple[int, Optional[int]]]
    _paused_reading: cython.bint

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
    ):
        self.id = uuid.uuid4()
        self.logger = _resolve_logger(logger)
        self.transport = cython.cast(WSTransport, None)
        self.request = cast(Request, None)
        self.response = cast(Response, None)
        self._subprotocols = subprotocols
        self._subprotocol = cast(Optional[Subprotocol], None)
        self._state = State.CONNECTING
        self._close_exc: Optional[ConnectionClosed] = None
        self._loop = asyncio.get_running_loop()
        self._frames = _SingleConsumerQueue(self._loop)
        self._recv_in_progress = False
        self._send_in_progress = False
        self._send_waiters = deque()
        self._write_ready: Optional[asyncio.Future[None]] = None
        self._recv_streaming_broken = False
        self._pending_pings: dict[bytes, tuple[asyncio.Future[float], float]] = {}
        self._ping_interval = ping_interval
        self._ping_timeout = ping_timeout
        self._close_timeout = close_timeout
        self._keepalive_task: Optional[asyncio.Task[None]] = None
        self._latency = 0.0
        self._max_message_size = 0 if max_message_size is None else max_message_size
        self._max_queue_high, self._max_queue_low = _normalize_watermarks(max_queue)
        self._incoming_message_active = False
        self._incoming_message_size = 0
        self._write_limit = write_limit
        self._paused_reading = False

    @cython.ccall
    def on_ws_connected(self, transport: WSTransport) -> None:
        self.transport = transport
        self.request = transport.request
        self.response = transport.response
        self._subprotocol = _resolve_subprotocol(self._subprotocols, self.response)
        self._state = State.OPEN
        self._set_write_limits(self._write_limit)
        if self._ping_interval is not None and self._keepalive_task is None:
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    @cython.ccall
    def on_ws_disconnected(self, transport: WSTransport) -> None:
        self._state = State.CLOSED
        self._set_close_exception()
        self._frames.put(None)
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

    @cython.ccall
    def on_ws_frame(self, transport: WSTransport, frame: WSFrame) -> None:
        if frame.msg_type == WSMsgType.PONG:
            ping = self._pending_pings.pop(frame.get_payload_as_bytes(), None)
            if ping is not None:
                waiter, sent_at = ping
                self._latency = monotonic() - sent_at
                if not waiter.done():
                    waiter.set_result(self._latency)
            return

        if frame.msg_type == WSMsgType.CLOSE:
            close_code = frame.get_close_code()
            close_message = frame.get_close_message()
            self.transport.send_close(close_code, close_message)
            self.transport.disconnect()
            self._state = State.CLOSING
            return

        if frame.msg_type == WSMsgType.CONTINUATION:
            if not self._incoming_message_active:
                self._fail_protocol_error("unexpected continuation frame")
                return

            self._incoming_message_size += frame.payload_size
            if self._max_message_size > 0 and self._incoming_message_size > self._max_message_size:
                self._fail_message_too_big("message too big")
                return
            if frame.fin:
                self._incoming_message_active = False
                self._incoming_message_size = 0
        elif frame.msg_type in (WSMsgType.TEXT, WSMsgType.BINARY):
            if self._incoming_message_active:
                self._fail_protocol_error("expected continuation frame")
                return
            self._incoming_message_size = frame.payload_size
            if self._max_message_size > 0 and self._incoming_message_size > self._max_message_size:
                self._fail_message_too_big("message too big")
                return
            if frame.fin:
                self._incoming_message_size = 0
            else:
                self._incoming_message_active = True
        else:
            self._fail_protocol_error(f"unexpected opcode while receiving message: {frame.msg_type}")
            return

        self._frames.put(_BufferedFrame(frame.msg_type, frame.get_payload_as_bytes(), frame.fin))
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
        if self._max_queue_high > 0 and not self._paused_reading and self._frames.qsize() >= self._max_queue_high:
            self.transport.underlying_transport.pause_reading()
            self._paused_reading = True

    @cython.cfunc
    @cython.inline
    def _resume_reading_if_needed(self) -> None:
        if not self._paused_reading:
            return
        if self._max_queue_low == 0 or self._frames.qsize() <= self._max_queue_low:
            self.transport.underlying_transport.resume_reading()
            self._paused_reading = False

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
    def _check_frame(self, frame: Optional[_BufferedFrame]) -> None:
        self._resume_reading_if_needed()

        if frame is None:
            raise self._connection_closed()

    @cython.cfunc
    @cython.inline
    def _get_frame_nowait(self) -> object:
        return self._frames.get_nowait()

    async def recv(self, decode: Optional[bool] = None) -> Data:
        frame: Optional[_BufferedFrame]

        self._set_recv_in_progress()

        try:
            item = self._get_frame_nowait()
            if item is _QUEUE_EMPTY:
                item = await self._frames.get()

            frame = cython.cast(_BufferedFrame, item)
            self._check_frame(frame)

            msg_type = frame.msg_type
            if frame.fin:
                return self._decode_data(frame.payload, msg_type, decode)

            chunks = [frame.payload]
            while not frame.fin:
                frame = self._get_frame_nowait()
                if frame is _QUEUE_EMPTY:
                    frame = await self._frames.get()
                self._check_frame(frame)
                frame = cast(_BufferedFrame, frame)

                chunks.append(frame.payload)

            payload = b"".join(chunks)
            return self._decode_data(payload, msg_type, decode)
        finally:
            self._recv_in_progress = False

    def recv_streaming(self, decode: Optional[bool] = None) -> AsyncIterator[Data]:
        self._set_recv_in_progress()

        msg_started: cython.bint = False
        msg_finished: cython.bint = False

        async def iterator() -> AsyncIterator[Data]:
            nonlocal msg_started, msg_finished
            frame: Optional[_BufferedFrame]
            msg_type: WSMsgType

            try:
                frame = self._get_frame_nowait()
                if frame is _QUEUE_EMPTY:
                    frame = await self._frames.get()
                self._check_frame(frame)
                frame = cast(_BufferedFrame, frame)
                msg_started = True
                msg_type = frame.msg_type
                yield self._decode_data(frame.payload, msg_type, decode)

                while not frame.fin:
                    frame = self._get_frame_nowait()
                    if frame is _QUEUE_EMPTY:
                        frame = await self._frames.get()
                    self._check_frame(frame)
                    frame = cast(_BufferedFrame, frame)
                    yield cast(Data, self._decode_data(frame.payload, msg_type, decode))
                msg_finished = True
            finally:
                self._recv_in_progress = False
                if msg_started and not msg_finished:
                    self._recv_streaming_broken = True
                elif msg_finished:
                    self._recv_streaming_broken = False

        return iterator()

    async def send(
        self,
        message: Union[DataLike, Iterable[DataLike], AsyncIterator[DataLike]],
        text: Optional[bool] = None,
    ) -> None:
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
                self.transport.send(msg_type, message)
                if self._write_ready is not None:
                    await self._write_ready
            elif isinstance(message, AsyncIterable):
                await self._send_fragments(True, message.__aiter__(), text)
            elif isinstance(message, Iterable):
                await self._send_fragments(False, iter(message), text)
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

    async def _send_fragments(
        self,
        is_async: cython.bint,
        iterator: Union[Iterator[DataLike], AsyncIterator[DataLike]],
        text: Optional[bool],
    ) -> None:
        stop_exception_type = StopAsyncIteration if is_async else StopIteration
        try:
            if is_async:
                first = await anext(cast(AsyncIterator[DataLike], iterator))
            else:
                first = next(cast(Iterator[DataLike], iterator))
        except stop_exception_type:
            raise TypeError("message iterable cannot be empty") from None

        first_is_str: cython.bint
        if isinstance(first, str):
            msg_type = WSMsgType.BINARY if text is False else WSMsgType.TEXT
            first_is_str = True
        elif isinstance(first, (bytes, bytearray, memoryview)):
            msg_type = WSMsgType.TEXT if text else WSMsgType.BINARY
            first_is_str = False
        else:
            raise TypeError(f"message must contain str or bytes-like objects, got {type(first).__name__}")

        previous = first
        while True:
            try:
                if is_async:
                    current = await anext(cast(AsyncIterator[DataLike], iterator))
                else:
                    current = next(cast(Iterator[DataLike], iterator))
            except stop_exception_type:
                break

            self._check_fragment_type(current, first_is_str)

            self.transport.send(msg_type, previous, fin=False)
            msg_type = WSMsgType.CONTINUATION
            if self._write_ready is not None:
                await self._write_ready

            previous = current

        self.transport.send(msg_type, previous, fin=True)
        if self._write_ready is not None:
            await self._write_ready

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
        payload = data.encode("utf-8") if isinstance(data, str) else data
        self.transport.send_pong(payload)

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

    async def __aenter__(self) -> ClientConnection:
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
    def local_address(self) -> Any:
        return self.transport.underlying_transport.get_extra_info("sockname")

    @property
    def remote_address(self) -> Any:
        return self.transport.underlying_transport.get_extra_info("peername")

    @property
    def latency(self) -> float:
        return cast(float, self._latency)

    @property
    def subprotocol(self) -> Optional[Subprotocol]:
        return self._subprotocol

    @property
    def close_code(self) -> Optional[int]:
        handshake = self.transport.close_handshake
        if handshake is None:
            return None
        if handshake.recv is not None:
            return cast(Optional[int], _coerce_close_code(handshake.recv.code))
        if handshake.sent is not None:
            return cast(Optional[int], _coerce_close_code(handshake.sent.code))
        return None

    @property
    def close_reason(self) -> Optional[str]:
        handshake = self.transport.close_handshake
        if handshake is None:
            return None
        if handshake.recv is not None:
            return cast(Optional[str], _coerce_close_reason(handshake.recv.reason))
        if handshake.sent is not None:
            return cast(Optional[str], _coerce_close_reason(handshake.sent.reason))
        return None
