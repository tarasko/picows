from __future__ import annotations

import asyncio
import sys
import logging
import os
import socket
import uuid
import warnings
from collections.abc import AsyncIterable, Generator, Iterable
from enum import IntEnum
from ssl import SSLContext
from time import monotonic
from typing import Any, AsyncIterator, Awaitable, Callable, Optional, Sequence, \
    Union, cast, Dict, Tuple
from urllib.request import getproxies

import cython

if cython.compiled:
    from cython.cimports.picows.picows import WSListener, WSTransport, WSFrame, \
        WSMsgType, WSCloseCode
else:
    from picows import WSListener, WSTransport, WSFrame, WSMsgType, WSCloseCode


import picows
from picows.types import WSHeadersLike
from picows.url import parse_url

from ..exceptions import (
    ConcurrencyError,
    ConnectionClosed,
    ConnectionClosedError,
    ConnectionClosedOK,
    InvalidHandshake,
    InvalidHeader,
    InvalidMessage,
    InvalidStatus,
    InvalidUpgrade,
    InvalidURI,
    PayloadTooBig,
    ProtocolError,
)


Data = Union[str, bytes, bytearray, memoryview]
HeadersLike = WSHeadersLike
CloseCodeT = int
LoggerLike = Union[str, logging.Logger, logging.LoggerAdapter[Any], None]


OK_CLOSE_CODES = {0, 1000, 1001}


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


@cython.cfunc
def _coerce_close_code(code: WSCloseCode) -> Optional[int]:
    return None if code is None else int(code)


@cython.cfunc
def _coerce_close_reason(reason: Optional[str]) -> Optional[str]:
    return reason if reason is not None else None


@cython.cfunc
def _header_items(headers: Any) -> list[tuple[str, str]]:
    return [] if headers is None else list(headers.items())


@cython.cfunc
def _resolve_subprotocol(subprotocols: Optional[Sequence[str]], response: Any) -> Optional[str]:
    if response is None:
        return None
    value = response.headers.get("Sec-WebSocket-Protocol")
    if value is None:
        return None
    if subprotocols is not None and value not in subprotocols:
        raise InvalidHandshake(f"unsupported subprotocol negotiated by server: {value}")
    return cast(str, value)


@cython.cfunc
def _default_user_agent() -> str:
    return f"Python/{sys.version_info.major}.{sys.version_info.minor} picows-websockets/0"


@cython.cfunc
def _process_proxy(proxy: Union[str, bool, None], secure: bool) -> Optional[str]:
    if proxy is None:
        return None
    if isinstance(proxy, str):
        return proxy
    if proxy is True:
        proxies = getproxies()
        return (
            proxies.get("wss" if secure else "ws")
            or proxies.get("https" if secure else "http")
        )
    raise InvalidURI(str(proxy), "proxy must be None, True, or a proxy URL")


@cython.cfunc
def _normalize_size_limit(limit: Optional[int]) -> cython.Py_ssize_t:
    return 0 if limit is None else limit


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
class ClientConnection(WSListener):
    id: uuid.UUID
    logger: Union[logging.Logger, logging.LoggerAdapter[Any]]
    transport: WSTransport
    request: picows.WSUpgradeRequest
    response: picows.WSUpgradeResponse
    _subprotocols: Optional[Sequence[str]]
    _subprotocol: Optional[str]
    _state: State
    _closed_event: asyncio.Event
    _frames: asyncio.Queue[Optional[_BufferedFrame]]
    _close_exc: Optional[ConnectionClosed]
    _loop: asyncio.AbstractEventLoop
    _recv_lock: asyncio.Lock
    _send_lock: asyncio.Lock
    _write_ready: Optional[asyncio.Future[None]]
    _recv_streaming_in_progress: cython.bint
    _recv_streaming_broken: cython.bint
    _pending_pings: Dict[bytes, Tuple[asyncio.Future[float], float]]
    _ping_interval: Optional[float]
    _ping_timeout: Optional[float]
    _close_timeout: Optional[float]
    _keepalive_task: Optional[asyncio.Task[None]]
    _latency: cython.double
    _max_message_size: cython.Py_ssize_t
    _max_fragment_size: cython.Py_ssize_t
    _max_queue_high: cython.Py_ssize_t
    _max_queue_low: cython.Py_ssize_t
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
        max_fragment_size: Optional[int] = 1024 * 1024,
        logger: LoggerLike = None,
        subprotocols: Optional[Sequence[str]] = None,
    ):
        self.id = uuid.uuid4()
        self.logger = self._resolve_logger(logger)
        self.transport = cython.cast(WSTransport, None)
        self.request = cast(picows.WSUpgradeRequest, None)
        self.response = cast(picows.WSUpgradeResponse, None)
        self._subprotocols = subprotocols
        self._subprotocol = cast(Optional[str], None)
        self._state = State.CONNECTING
        self._closed_event = asyncio.Event()
        self._frames: asyncio.Queue[Optional[_BufferedFrame]] = asyncio.Queue()
        self._close_exc: Optional[ConnectionClosed] = None
        self._loop = asyncio.get_running_loop()
        self._recv_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self._write_ready: Optional[asyncio.Future[None]] = None
        self._recv_streaming_in_progress = False
        self._recv_streaming_broken = False
        self._pending_pings: dict[bytes, tuple[asyncio.Future[float], float]] = {}
        self._ping_interval = ping_interval
        self._ping_timeout = ping_timeout
        self._close_timeout = close_timeout
        self._keepalive_task: Optional[asyncio.Task[None]] = None
        self._latency = 0.0
        self._max_message_size = _normalize_size_limit(max_message_size)
        self._max_fragment_size = _normalize_size_limit(max_fragment_size)
        self._max_queue_high, self._max_queue_low = self._normalize_watermarks(max_queue)
        self._write_limit = write_limit
        self._paused_reading = False

    @cython.cfunc
    def _resolve_logger(self, logger: LoggerLike) -> Union[logging.Logger, logging.LoggerAdapter[Any]]:
        if logger is None:
            return logging.getLogger("websockets.client")
        if isinstance(logger, str):
            return logging.getLogger(logger)
        return logger

    @cython.cfunc
    def _normalize_watermarks(
        self,
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
    def _set_write_limits(self, write_limit: Union[int, tuple[int, Optional[int]]]) -> None:
        if isinstance(write_limit, tuple):
            high, low = write_limit
        else:
            high, low = write_limit, None
        self.transport.underlying_transport.set_write_buffer_limits(high=high, low=low)

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
    def _pause_reading_if_needed(self) -> None:
        if self._max_queue_high > 0 and not self._paused_reading and self._frames.qsize() >= self._max_queue_high:
            self.transport.underlying_transport.pause_reading()
            self._paused_reading = True

    @cython.cfunc
    def _resume_reading_if_needed(self) -> None:
        if not self._paused_reading:
            return
        if self._max_queue_low == 0 or self._frames.qsize() <= self._max_queue_low:
            self.transport.underlying_transport.resume_reading()
            self._paused_reading = False

    @cython.cfunc
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

    @cython.ccall
    def on_ws_disconnected(self, transport: WSTransport) -> None:
        self._state = State.CLOSED
        self._set_close_exception()
        self._frames.put_nowait(None)
        self._closed_event.set()
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
    def _fail_message_too_big(self, message: str) -> None:
        self.transport.send_close(WSCloseCode.MESSAGE_TOO_BIG, message.encode("utf-8"))
        self.transport.disconnect(False)

    @cython.ccall
    def on_ws_frame(self, transport: WSTransport, frame: WSFrame) -> None:
        payload = frame.get_payload_as_bytes()
        if frame.msg_type == WSMsgType.PING:
            self.transport.send_pong(payload)
            return

        if frame.msg_type == WSMsgType.PONG:
            ping = self._pending_pings.pop(payload, None)
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

        if self._max_fragment_size > 0 and len(payload) > self._max_fragment_size:
            self._fail_message_too_big("fragment too big")
            return

        self._frames.put_nowait(_BufferedFrame(frame.msg_type, payload, frame.fin))
        self._pause_reading_if_needed()

    async def _next_frame(self) -> _BufferedFrame:
        frame: _BufferedFrame = cython.cast(_BufferedFrame, await self._frames.get())
        self._resume_reading_if_needed()
        if frame is None:
            raise self._connection_closed()
        return frame

    @cython.cfunc
    def _connection_closed(self) -> ConnectionClosed:
        if self._close_exc is None:
            self._set_close_exception()
        return self._close_exc or ConnectionClosedError(None, None, None)

    @cython.cfunc
    def _ensure_recv_available(self) -> None:
        if self._recv_streaming_broken:
            raise ConcurrencyError("recv_streaming() wasn't fully consumed")
        if self._recv_streaming_in_progress:
            raise ConcurrencyError("cannot call recv() while recv_streaming() is active")

    async def recv(self, decode: Optional[bool] = None) -> Union[str, bytes]:
        self._ensure_recv_available()
        if self._recv_lock.locked():
            raise ConcurrencyError("cannot call recv() concurrently")
        async with self._recv_lock:
            first: _BufferedFrame = await self._next_frame()
            if first.msg_type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                raise ProtocolError(f"unexpected opcode while receiving message: {first.msg_type}")
            msg_type = first.msg_type
            if first.fin:
                return self._decode_payload(first.payload, msg_type, decode)

            chunks = [first.payload]
            total: cython.Py_ssize_t = len(first.payload)
            while not first.fin:
                first = await self._next_frame()
                if first.msg_type != WSMsgType.CONTINUATION:
                    raise ProtocolError("expected continuation frame")
                chunks.append(first.payload)
                total += len(first.payload)
                if self._max_message_size > 0 and total > self._max_message_size:
                    self._fail_message_too_big("message too big")
                    raise PayloadTooBig("message too big")

            payload = b"".join(chunks)
            return self._decode_payload(payload, msg_type, decode)

    @cython.cfunc
    def _decode_payload(
        self,
        payload: bytes,
        msg_type: WSMsgType,
        decode: Optional[bool],
    ) -> Union[str, bytes]:
        if msg_type == WSMsgType.TEXT:
            if decode is False:
                return payload
            return payload.decode("utf-8")
        if decode is True:
            return payload.decode("utf-8")
        return payload

    def recv_streaming(self, decode: Optional[bool] = None) -> AsyncIterator[Union[str, bytes]]:
        self._ensure_recv_available()
        if self._recv_lock.locked():
            raise ConcurrencyError("cannot call recv_streaming() concurrently")
        self._recv_streaming_in_progress = True
        started = False
        finished = False

        async def iterator() -> AsyncIterator[Union[str, bytes]]:
            nonlocal started, finished
            try:
                async with self._recv_lock:
                    first: _BufferedFrame = await self._next_frame()
                    if first.msg_type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                        raise ProtocolError(f"unexpected opcode while receiving message: {first.msg_type}")
                    msg_type = first.msg_type
                    started = True
                    yield self._decode_fragment(first.payload, msg_type, decode)
                    total: cython.Py_ssize_t = len(first.payload)
                    frame = first
                    while not frame.fin:
                        frame: _BufferedFrame = await self._next_frame()
                        if frame.msg_type != WSMsgType.CONTINUATION:
                            raise ProtocolError("expected continuation frame")
                        total += len(frame.payload)
                        if self._max_message_size > 0 and total > self._max_message_size:
                            self._fail_message_too_big("message too big")
                            raise PayloadTooBig("message too big")
                        yield self._decode_fragment(frame.payload, msg_type, decode)
                finished = True
            finally:
                if started and not finished:
                    self._recv_streaming_broken = True
                elif finished:
                    self._recv_streaming_broken = False
                self._recv_streaming_in_progress = False

        return iterator()

    @cython.cfunc
    def _decode_fragment(
        self,
        payload: bytes,
        msg_type: WSMsgType,
        decode: Optional[bool],
    ) -> Union[str, bytes]:
        if msg_type == WSMsgType.TEXT:
            if decode is False:
                return payload
            return payload.decode("utf-8")
        if decode is True:
            return payload.decode("utf-8")
        return payload

    async def send(
        self,
        message: Union[Data, Iterable[Data], AsyncIterator[Data]],
        text: Optional[bool] = None,
    ) -> None:
        if self.state is State.CLOSED:
            raise self._connection_closed()

        async with self._send_lock:
            if isinstance(message, (str, bytes, bytearray, memoryview)):
                if isinstance(message, str):
                    self.transport.send(WSMsgType.TEXT, cython.cast(str, message).encode("utf-8"))
                else:
                    self.transport.send(
                        WSMsgType.TEXT if text else WSMsgType.BINARY,
                        message,
                    )
                if self._write_ready is not None:
                    await self._write_ready
                return
            if isinstance(message, AsyncIterable):
                await self._send_async_fragments(message, text)
                return
            if isinstance(message, Iterable):
                await self._send_sync_fragments(message, text)
                return
            raise TypeError(f"message has unsupported type {type(message).__name__}")

    async def _send_sync_fragments(self, message: Iterable[Data], text: Optional[bool]) -> None:
        iterator = iter(message)
        try:
            first = next(iterator)
        except StopIteration:
            raise TypeError("message iterable cannot be empty") from None

        msg_type, encode = self._get_fragment_codec(first, text)

        try:
            second = next(iterator)
        except StopIteration:
            self.transport.send(msg_type, encode(first))
            if self._write_ready is not None:
                await self._write_ready
            return

        self.transport.send(msg_type, encode(first), fin=False)
        if self._write_ready is not None:
            await self._write_ready
        previous = second
        for fragment in iterator:
            self.transport.send(WSMsgType.CONTINUATION, encode(previous), fin=False)
            if self._write_ready is not None:
                await self._write_ready
            previous = fragment
        self.transport.send(WSMsgType.CONTINUATION, encode(previous), fin=True)
        if self._write_ready is not None:
            await self._write_ready

    async def _send_async_fragments(self, message: AsyncIterable[Data], text: Optional[bool]) -> None:
        iterator = message.__aiter__()
        try:
            first = await anext(iterator)
        except StopAsyncIteration:
            raise TypeError("message iterable cannot be empty") from None

        msg_type, encode = self._get_fragment_codec(first, text)

        try:
            second = await anext(iterator)
        except StopAsyncIteration:
            self.transport.send(msg_type, encode(first))
            if self._write_ready is not None:
                await self._write_ready
            return

        self.transport.send(msg_type, encode(first), fin=False)
        if self._write_ready is not None:
            await self._write_ready
        previous = second
        async for fragment in iterator:
            self.transport.send(WSMsgType.CONTINUATION, encode(previous), fin=False)
            if self._write_ready is not None:
                await self._write_ready
            previous = fragment
        self.transport.send(WSMsgType.CONTINUATION, encode(previous), fin=True)
        if self._write_ready is not None:
            await self._write_ready

    @cython.cfunc
    def _get_fragment_codec(
        self,
        first: Data,
        text: Optional[bool],
    ) -> tuple[WSMsgType, Callable[[Data], bytes]]:
        if isinstance(first, str):
            def encode(item: Data) -> bytes:
                if not isinstance(item, str):
                    raise TypeError("all fragments must be of the same type")
                return item.encode("utf-8")

            return WSMsgType.TEXT, encode

        if isinstance(first, (bytes, bytearray, memoryview)):
            def encode(item: Data) -> Data:
                if not isinstance(item, (bytes, bytearray, memoryview)):
                    raise TypeError("all fragments must be of the same type")
                return item

            return (WSMsgType.TEXT if text else WSMsgType.BINARY), encode

        raise TypeError(f"message must contain str or bytes-like objects, got {type(first).__name__}")

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self.state is State.CLOSED:
            return
        if self.state is State.OPEN:
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
        await self._closed_event.wait()

    async def ping(self, data: Optional[Union[str, bytes]] = None) -> Awaitable[float]:
        if self.state is State.CLOSED:
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
        if self.state is State.CLOSED:
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

    async def _iterate_messages(self) -> AsyncIterator[Union[str, bytes]]:
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
        return self._latency

    @property
    def subprotocol(self) -> Optional[str]:
        return self._subprotocol

    @property
    def close_code(self) -> Optional[int]:
        handshake = self.transport.close_handshake
        if handshake is None:
            return None
        if handshake.recv is not None:
            return _coerce_close_code(handshake.recv.code)
        if handshake.sent is not None:
            return _coerce_close_code(handshake.sent.code)
        return None

    @property
    def close_reason(self) -> Optional[str]:
        handshake = self.transport.close_handshake
        if handshake is None:
            return None
        if handshake.recv is not None:
            return _coerce_close_reason(handshake.recv.reason)
        if handshake.sent is not None:
            return _coerce_close_reason(handshake.sent.reason)
        return None


class _Connect:
    def __init__(
        self,
        uri: str,
        *,
        origin: Optional[str] = None,
        extensions: Optional[Sequence[Any]] = None,
        subprotocols: Optional[Sequence[str]] = None,
        compression: Optional[str] = "deflate",
        additional_headers: Optional[HeadersLike] = None,
        user_agent_header: Optional[str] = _default_user_agent(),
        proxy: Union[str, bool, None] = True,
        process_exception: Callable[[Exception], Optional[Exception]] = process_exception,
        open_timeout: Optional[float] = 10,
        ping_interval: Optional[float] = 20,
        ping_timeout: Optional[float] = 20,
        close_timeout: Optional[float] = 10,
        max_size: Union[int, tuple[Optional[int], Optional[int]], None] = 1024 * 1024,
        max_queue: Union[int, tuple[Optional[int], Optional[int]], None] = 16,
        write_limit: Union[int, tuple[int, Optional[int]]] = 32768,
        logger: LoggerLike = None,
        create_connection: Optional[type[ClientConnection]] = None,
        **kwargs: Any,
    ):
        self.uri = uri
        self.origin = origin
        self.extensions = extensions
        self.subprotocols = subprotocols
        self.compression = compression
        self.additional_headers = additional_headers
        self.user_agent_header = user_agent_header
        self.proxy = proxy
        self.process_exception = process_exception
        self.open_timeout = open_timeout
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.close_timeout = close_timeout
        self.max_size = max_size
        self.max_queue = max_queue
        self.write_limit = write_limit
        self.logger = logger
        self.connection_factory = create_connection or ClientConnection
        self.kwargs = kwargs
        self._connection: Optional[ClientConnection] = None
        self._backoff = 1.0

    def __await__(self) -> Generator[Any, None, ClientConnection]:
        return self._connect().__await__()

    async def __aenter__(self) -> ClientConnection:
        self._connection = await self._connect()
        return self._connection

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._connection is not None:
            await self._connection.close()
            self._connection = None

    def __aiter__(self) -> _Connect:
        return self

    async def __anext__(self) -> ClientConnection:
        if self._connection is not None:
            await self._connection.close()
            self._connection = None
        while True:
            try:
                connection = await self._connect()
            except Exception as exc:
                processed = self.process_exception(exc)
                if processed is not None:
                    raise processed
                await asyncio.sleep(self._backoff)
                self._backoff = min(self._backoff * 2, 60.0)
                continue
            self._connection = connection
            self._backoff = 1.0
            return connection

    async def _connect(self) -> ClientConnection:
        parsed = parse_url(self.uri)
        proxy = _process_proxy(self.proxy, parsed.is_secure)
        extra_headers = self._build_headers()
        max_message_size, max_fragment_size = self._normalize_max_size(self.max_size)

        if self.extensions is not None:
            raise NotImplementedError("custom extensions aren't supported by picows.websockets")
        if self.compression not in (None, "deflate"):
            raise NotImplementedError("only compression=None or 'deflate' are accepted")
        if self.compression == "deflate":
            warnings.warn(
                "picows.websockets doesn't implement permessage-deflate; connecting without compression",
                RuntimeWarning,
                stacklevel=2,
            )

        conn_kwargs = dict(self.kwargs)
        ssl_context = conn_kwargs.pop("ssl", None)
        host_override = conn_kwargs.pop("host", None)
        port_override = conn_kwargs.pop("port", None)
        preexisting_sock = conn_kwargs.pop("sock", None)

        socket_factory = conn_kwargs.pop("socket_factory", None)
        if preexisting_sock is not None:
            if socket_factory is not None:
                raise TypeError("cannot pass both sock and socket_factory")

            provided_sock = cast(socket.socket, preexisting_sock)

            def provided_socket(_: Any) -> socket.socket:
                return provided_sock

            socket_factory = provided_socket
        elif host_override is not None or port_override is not None:
            if socket_factory is not None:
                raise TypeError("cannot pass both host/port override and socket_factory")

            async def connect_override(_: Any) -> socket.socket:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                await asyncio.get_running_loop().sock_connect(
                    sock,
                    (host_override or parsed.host, port_override or parsed.port),
                )
                return sock

            socket_factory = connect_override
        def listener_factory() -> ClientConnection:
            return self.connection_factory(
                ping_interval=self.ping_interval,
                ping_timeout=self.ping_timeout,
                close_timeout=self.close_timeout,
                max_queue=self.max_queue,
                write_limit=self.write_limit,
                max_message_size=max_message_size,
                max_fragment_size=max_fragment_size,
                logger=self.logger,
                subprotocols=self.subprotocols,
            )

        try:
            _transport, listener = await picows.ws_connect(
                listener_factory,
                self.uri,
                ssl_context=self._coerce_ssl_context(ssl_context),
                websocket_handshake_timeout=self.open_timeout,
                enable_auto_ping=False,
                enable_auto_pong=False,
                max_frame_size=max_fragment_size if max_fragment_size > 0 else 2 ** 31 - 1,
                extra_headers=extra_headers,
                proxy=proxy,
                socket_factory=socket_factory,
                logger_name=self.logger if self.logger is not None else "websockets.client",
                **conn_kwargs,
            )
        except picows.WSInvalidURL as exc:
            raise InvalidURI(exc.args[0], exc.args[1] if len(exc.args) > 1 else str(exc)) from exc
        except picows.WSInvalidStatusError as exc:
            raise InvalidStatus(exc.response) from exc
        except picows.WSInvalidUpgradeError as exc:
            raise InvalidUpgrade(exc.name, exc.value) from exc
        except picows.WSInvalidHeaderError as exc:
            raise InvalidHeader(exc.name, exc.value) from exc
        except picows.WSInvalidMessageError as exc:
            raise InvalidMessage(str(exc)) from exc
        except picows.WSHandshakeError as exc:
            raise InvalidHandshake(str(exc)) from exc

        return cython.cast(ClientConnection, listener)

    def _normalize_max_size(
        self,
        max_size: Union[int, tuple[Optional[int], Optional[int]], None],
    ) -> tuple[cython.Py_ssize_t, cython.Py_ssize_t]:
        if max_size is None:
            return 0, 0
        if isinstance(max_size, tuple):
            max_message_size, max_fragment_size = max_size
            return _normalize_size_limit(max_message_size), _normalize_size_limit(max_fragment_size)
        return max_size, max_size

    def _build_headers(self) -> list[tuple[str, str]]:
        headers = _header_items(self.additional_headers)
        if self.origin is not None:
            headers.append(("Origin", self.origin))
        if self.user_agent_header is not None:
            headers.append(("User-Agent", self.user_agent_header))
        if self.subprotocols:
            headers.append(("Sec-WebSocket-Protocol", ", ".join(self.subprotocols)))
        return headers

    def _coerce_ssl_context(self, value: Any) -> Optional[SSLContext]:
        if value in (None, True):
            return None
        if value is False:
            raise NotImplementedError("ssl=False isn't supported for wss:// URIs")
        if not isinstance(value, SSLContext):
            raise TypeError("ssl must be an SSLContext, True, False, or None")
        return value


def connect(uri: str, **kwargs: Any) -> _Connect:
    return _Connect(uri, **kwargs)
