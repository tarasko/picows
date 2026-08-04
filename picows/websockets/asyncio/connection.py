from __future__ import annotations

import asyncio
import os
import uuid
import warnings
import zlib
from collections import deque
from collections.abc import AsyncIterable, Iterable
from time import monotonic
from typing import Any, AsyncIterator, Awaitable, Optional, \
    Union, Dict, Tuple, Iterator, Mapping, NoReturn

import cython

if cython.compiled:
    from cython.cimports.picows.picows import WSListener, WSTransport, WSFrame, \
        WSMsgType, WSCloseCode
else:
    from picows import WSListener, WSTransport, WSFrame, WSMsgType, WSCloseCode

from picows import WSProtocolError

from .utils import normalize_watermarks
from ..compat import State, CloseCode, Request, Response
from ..exceptions import (
    ConcurrencyError,
    ConnectionClosed,
    ConnectionClosedError,
    ConnectionClosedOK,
    InvalidHandshake,
    InvalidStatus,
)
from ..typing import BytesLike, Data, DataLike, LoggerProtocol, Subprotocol


# cached for performance
_ok_close_codes = cython.declare(set, {0, 1000, 1001})
_asyncio_shield = cython.declare(object, asyncio.shield)

# zlib/compress/decompress utils, cached for performance
_empty_uncompressed_block = cython.declare(bytes, b"\x00\x00\xff\xff")
_zlib_compressobj = cython.declare(object, zlib.compressobj)
_zlib_decompressobj = cython.declare(object, zlib.decompressobj)
_zlib_z_sync_flush = cython.declare(object, zlib.Z_SYNC_FLUSH)


@cython.freelist(128)
@cython.no_gc
@cython.cclass
class _BufferedFrame:
    msg_type: WSMsgType
    payload: bytes
    fin: cython.bint


@cython.cfunc
@cython.inline
def _make_buffered_frame(msg_type: WSMsgType, payload: bytes, fin: cython.bint) -> _BufferedFrame:
    self: _BufferedFrame = _BufferedFrame.__new__(_BufferedFrame)
    self.msg_type = msg_type
    self.payload = payload
    self.fin = fin
    return self


@cython.no_gc
@cython.cclass
class _PerMessageDeflate:
    remote_no_context_takeover: cython.bint
    local_no_context_takeover: cython.bint
    remote_max_window_bits: int
    local_max_window_bits: int
    _decoder: Any
    _encoder: Any
    _decode_cont_data: cython.bint

    @classmethod
    def from_response_header(cls, header_value: str) -> _PerMessageDeflate:
        extensions = [item.strip() for item in header_value.split(",") if item.strip()]
        if len(extensions) != 1:
            raise InvalidHandshake("unsupported websocket extension negotiation")

        parts = [item.strip() for item in extensions[0].split(";")]
        if not parts or parts[0] != "permessage-deflate":
            raise InvalidHandshake("unsupported websocket extension negotiation")

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
                raise InvalidHandshake(
                    f"unsupported websocket extension negotiation: {name}")
            seen.add(name)

            if name == "server_no_context_takeover":
                if value is not None:
                    raise InvalidHandshake("invalid server_no_context_takeover value")
                server_no_context_takeover = True
            elif name == "client_no_context_takeover":
                if value is not None:
                    raise InvalidHandshake("invalid client_no_context_takeover value")
                client_no_context_takeover = True
            elif name == "server_max_window_bits":
                if value is None or not value.isdigit():
                    raise InvalidHandshake("invalid server_max_window_bits value")
                server_max_window_bits = int(value)
                if not 8 <= server_max_window_bits <= 15:
                    raise InvalidHandshake("invalid server_max_window_bits value")
            elif name == "client_max_window_bits":
                if value is None or not value.isdigit():
                    raise InvalidHandshake("invalid client_max_window_bits value")
                client_max_window_bits = int(value)
                if not 8 <= client_max_window_bits <= 15:
                    raise InvalidHandshake("invalid client_max_window_bits value")
            else:
                raise InvalidHandshake(f"unsupported extension parameter: {name}")

        self: _PerMessageDeflate = _PerMessageDeflate.__new__(_PerMessageDeflate)
        self.remote_no_context_takeover = server_no_context_takeover
        self.local_no_context_takeover = client_no_context_takeover
        self.remote_max_window_bits = -(server_max_window_bits or 15)
        self.local_max_window_bits = -(client_max_window_bits or 15)
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
            self._decoder = _zlib_decompressobj(wbits=self.remote_max_window_bits)
        if not self.local_no_context_takeover:
            self._encoder = _zlib_compressobj(wbits=self.local_max_window_bits)

        return self

    @cython.ccall
    def decode_frame(self, frame: WSFrame, max_length: cython.Py_ssize_t) -> bytes:
        data: bytes
        data2: bytes

        if frame.msg_type == WSMsgType.CONTINUATION:
            if frame.rsv1:
                raise WSProtocolError(WSCloseCode.PROTOCOL_ERROR, "unexpected rsv1 on continuation frame")
            if not self._decode_cont_data:
                return frame.get_payload_as_bytes() # type: ignore[no-any-return]
            if frame.fin:
                self._decode_cont_data = False
        else:
            if not frame.rsv1:
                return frame.get_payload_as_bytes() # type: ignore[no-any-return]
            if not frame.fin:
                self._decode_cont_data = True
            if self.remote_no_context_takeover or self._decoder is None:
                self._decoder = _zlib_decompressobj(wbits=self.remote_max_window_bits)

        try:
            data = self._decoder.decompress(frame.get_payload_as_memoryview(), max_length)
            if max_length > 0:
                max_length -= len(data)

                if self._decoder.unconsumed_tail:
                    raise WSProtocolError(WSCloseCode.MESSAGE_TOO_BIG,
                                          "message too big")

            if frame.fin:
                data2 = self._decoder.decompress(_empty_uncompressed_block, max_length)
                if data2:
                    data += data2
        except zlib.error as exc:
            raise WSProtocolError(WSCloseCode.PROTOCOL_ERROR,
                                  "decompression failed") from exc

        if frame.fin and self.remote_no_context_takeover:
            self._decoder = None

        return data

    @cython.ccall
    @cython.wraparound(True)
    def encode_frame(self, msg_type: WSMsgType, data: DataLike, fin: cython.bint) -> BytesLike:
        if msg_type != WSMsgType.CONTINUATION and (self.local_no_context_takeover or self._encoder is None):
            self._encoder = _zlib_compressobj(wbits=self.local_max_window_bits)

        if isinstance(data, str):
            data = cython.cast(str, data).encode('utf-8')

        compressed_data: BytesLike = (self._encoder.compress(data) +
                                      self._encoder.flush(_zlib_z_sync_flush))
        if fin:
            mv = memoryview(compressed_data)
            assert mv[-4:] == _empty_uncompressed_block
            compressed_data = mv[:-4]
            if self.local_no_context_takeover:
                self._encoder = None

        return compressed_data


@cython.cfunc
@cython.inline
def _coerce_close_code(code: CloseCode) -> Optional[int]:
    return None if code is None else code  # type: ignore[return-value]


@cython.cfunc
@cython.inline
def _coerce_close_reason(reason: Optional[str]) -> Optional[str]:
    return reason if reason is not None else None


@cython.ccall
def process_exception(exc: Exception) -> Optional[Exception]:
    if isinstance(exc, (EOFError, OSError, asyncio.TimeoutError)):
        return None
    if isinstance(exc, InvalidStatus):
        status = exc.response.status_code
        if int(status) in {500, 502, 503, 504}:
            return None
    return exc


@cython.cclass
class ConnectionBase(WSListener):  # type: ignore[misc]
    id: uuid.UUID
    logger: LoggerProtocol
    transport: WSTransport
    _request: Request
    _response: Response
    _subprotocol: Optional[Subprotocol]
    _permessage_deflate: Optional[_PerMessageDeflate]
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
    _recv_queue: deque[_BufferedFrame]
    _max_message_size: cython.Py_ssize_t        # 0 - no limit
    _max_frame_size: cython.Py_ssize_t          # 0 - no limit
    _max_queue_high: cython.Py_ssize_t          # 0 - no limit
    _max_queue_low: cython.Py_ssize_t           # 0 - no limit
    _incoming_message_active: cython.bint
    _incoming_message_size: cython.Py_ssize_t

    # Close logic
    _close_timeout: Optional[float]
    _close_fut: asyncio.Future[None]
    _close_exc: Optional[ConnectionClosed]

    _pending_pings: Dict[bytes, Tuple[asyncio.Future[float], float]]
    _ping_interval: Optional[float]
    _ping_timeout: Optional[float]
    _keepalive_task: Optional[asyncio.Task[None]]
    _latency: cython.double

    def __init__(
        self,
        *,
        request: Request,
        response: Response,
        subprotocol: Optional[Subprotocol],
        permessage_deflate: Optional[_PerMessageDeflate],
        ping_interval: Optional[float],
        ping_timeout: Optional[float],
        close_timeout: Optional[float],
        max_queue: Union[int, tuple[Optional[int], Optional[int]], None],
        write_limit: Union[int, tuple[int, Optional[int]]],
        max_message_size: Optional[int],
        max_frame_size: Optional[int],
        logger: LoggerProtocol,
    ):
        self.id = uuid.uuid4()
        self.logger = logger
        self.transport = cython.cast(WSTransport, None)
        self._request = request
        self._response = response
        self._subprotocol = subprotocol
        self._permessage_deflate = permessage_deflate
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
        self._max_frame_size = 0 if max_frame_size is None else max_frame_size
        self._max_queue_high, self._max_queue_low = normalize_watermarks(max_queue)
        self._incoming_message_active = False
        self._incoming_message_size = 0

        self._close_timeout = close_timeout
        self._close_fut = self._loop.create_future()
        self._close_exc: Optional[ConnectionClosed] = None

        self._pending_pings: dict[bytes, tuple[asyncio.Future[float], float]] = {}
        self._ping_interval = ping_interval
        self._ping_timeout = ping_timeout
        self._keepalive_task: Optional[asyncio.Task[None]] = None
        self._latency = 0.0

    @cython.ccall
    def on_ws_connected(self, transport: WSTransport) -> None:
        self.transport = transport
        self._set_write_limits(self._write_limit)
        if self._ping_interval is not None and self._keepalive_task is None:
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    @cython.ccall
    def on_ws_disconnected(self, transport: WSTransport) -> None:
        # Set _close_exc, _close_fut
        self._set_close_exception()

        # Pacify type checker
        assert self._close_exc is not None

        # Wake up potential waiter on _recv_queue
        if self._recv_waiter is not None:
            if not self._recv_waiter.done():
                self._recv_waiter.set_exception(self._close_exc)
            self._recv_waiter = None

        # Cancel pinging loop
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            self._keepalive_task = None

        # If there is a waiter waiting for resume_writing wake it up with exception
        if self._write_ready is not None:
            if not self._write_ready.done():
                self._write_ready.set_exception(self._close_exc)
            self._write_ready = None

        # Wake up all waiters waiting for ping replies
        for ping_waiter, _ in self._pending_pings.values():
            if not ping_waiter.done():
                ping_waiter.set_exception(self._close_exc)
        self._pending_pings.clear()

        # Wake up all waiters waiting for current send to complete
        for send_waiter in self._send_waiters:
            if not send_waiter.done():
                send_waiter.set_exception(self._close_exc)
        self._send_waiters.clear()

    @cython.ccall
    def on_ws_frame(self, transport: WSTransport, frame: WSFrame) -> None:
        if frame.msg_type == WSMsgType.PONG:
            self._process_pong_frame(frame)
            return

        if frame.msg_type == WSMsgType.CLOSE:
            self._process_close_frame(frame)
            return

        if frame.msg_type not in (WSMsgType.TEXT, WSMsgType.BINARY, WSMsgType.CONTINUATION):
            raise WSProtocolError(WSCloseCode.PROTOCOL_ERROR, "unsupported frame opcode")

        if self._max_frame_size > 0 and frame.payload_size > self._max_frame_size:
            raise WSProtocolError(
                WSCloseCode.MESSAGE_TOO_BIG,
                f"frame with {frame.payload_size} bytes exceeds limit of {self._max_frame_size} bytes",
            )

        if self._permessage_deflate is None and frame.rsv1:
            raise WSProtocolError(
                WSCloseCode.PROTOCOL_ERROR,
                "received compressed frame without negotiated permessage-deflate",
            )

        if frame.msg_type == WSMsgType.CONTINUATION and not self._incoming_message_active:
            raise WSProtocolError(WSCloseCode.PROTOCOL_ERROR, "unexpected continuation frame")

        if frame.msg_type != WSMsgType.CONTINUATION and self._incoming_message_active:
            raise WSProtocolError(WSCloseCode.PROTOCOL_ERROR, "expected continuation frame")

        payload: bytes
        if self._permessage_deflate is not None:
            remaining = 0 if self._max_message_size == 0 else (
                max(self._max_message_size - self._incoming_message_size, 0))
            payload = self._permessage_deflate.decode_frame(frame, remaining)
        else:
            payload = frame.get_payload_as_bytes()

        if frame.msg_type == WSMsgType.CONTINUATION:
            self._incoming_message_size += len(payload)
        else:
            self._incoming_message_size = len(payload)

        if self._max_message_size > 0 and self._incoming_message_size > self._max_message_size:
            raise WSProtocolError(WSCloseCode.MESSAGE_TOO_BIG, "message too big")

        if frame.msg_type == WSMsgType.CONTINUATION:
            if frame.fin:
                self._incoming_message_active = False
                self._incoming_message_size = 0
        else:
            if frame.fin:
                self._incoming_message_size = 0
            else:
                self._incoming_message_active = True

        self._add_to_recv_queue(_make_buffered_frame(frame.msg_type, payload, frame.fin))
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
    def _add_to_recv_queue(self, frame: _BufferedFrame) -> None:
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
        if self._close_exc is not None:
            raise self._close_exc

        waiter: asyncio.Future[None] = self._loop.create_future()
        self._recv_waiter = waiter
        return waiter

    @cython.cfunc
    @cython.inline
    def _set_close_exception(self) -> None:
        handshake = self.transport.close_handshake
        if handshake is None:
            self._close_exc = ConnectionClosedError(None, None, None)
            self._close_fut.set_result(None)
            return
        rcvd = handshake.recv
        sent = handshake.sent
        rcvd_then_sent = handshake.recv_then_sent
        rcvd_code = _coerce_close_code(rcvd.code) if rcvd is not None else None
        sent_code = _coerce_close_code(sent.code) if sent is not None else None
        ok = (
            (rcvd_code in _ok_close_codes or rcvd_code is None)
            and (sent_code in _ok_close_codes or sent_code is None)
        )
        exc_type = ConnectionClosedOK if ok else ConnectionClosedError
        self._close_exc = exc_type(rcvd, sent, rcvd_then_sent)
        self._close_fut.set_result(None)

    @cython.cfunc
    @cython.inline
    def _set_recv_in_progress(self) -> None:
        if self._recv_in_progress:
            raise ConcurrencyError("cannot call recv() or recv_streaming() concurrently")
        if self._recv_streaming_broken:
            raise ConcurrencyError("recv_streaming() wasn't fully consumed")
        self._recv_in_progress = True

    @cython.cfunc
    @cython.inline
    def _decode_data(self, payload: bytes, msg_type: WSMsgType, decode: Optional[bool]) -> Data:
        if decode is True or (msg_type == WSMsgType.TEXT and decode is None):
            return payload.decode("utf-8")
        else:
            return payload

    @cython.cfunc
    @cython.inline
    def _check_frame(self, frame: _BufferedFrame) -> _BufferedFrame:
        self._resume_reading_if_needed()
        return frame

    @cython.cfunc
    @cython.inline
    def _fail_invalid_data(self, exc: UnicodeDecodeError) -> None:
        self.transport.send_close(
            WSCloseCode.INVALID_TEXT,
            f"{exc.reason} at position {exc.start}",
        )
        self.transport.disconnect(False)

    async def recv(self, decode: Optional[bool] = None) -> Data:
        frame: _BufferedFrame

        self._set_recv_in_progress()

        try:
            if not self._recv_queue:
                await self._wait_recv_queue_not_empty()
            frame = self._check_frame(self._recv_queue.popleft())

            msg_type = frame.msg_type
            if frame.fin:
                data: Data = self._decode_data(frame.payload, msg_type, decode)
                return data

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
                data = self._decode_data(payload, msg_type, decode)
                return data
            except asyncio.CancelledError:
                self._recv_queue.extendleft(reversed(frames))
                raise
        except UnicodeDecodeError as exc:
            self._fail_invalid_data(exc)
            await self._wait_close_and_raise(exc)
        finally:
            self._recv_in_progress = False
            self._recv_waiter = None

    def recv_streaming(self, decode: Optional[bool] = None) -> AsyncIterator[Data]:
        msg_started: cython.bint = False
        msg_finished: cython.bint = False
        frame: _BufferedFrame
        msg_type: WSMsgType

        async def iterator() -> AsyncIterator[Data]:
            nonlocal msg_started, msg_finished

            try:
                self._set_recv_in_progress()
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
            except UnicodeDecodeError as exc:
                self._fail_invalid_data(exc)
                await self._wait_close_and_raise(exc)
            finally:
                self._recv_in_progress = False
                self._recv_waiter = None
                if msg_started and not msg_finished:
                    self._recv_streaming_broken = True
                elif msg_finished:
                    self._recv_streaming_broken = False

        return iterator()

    @cython.cfunc
    @cython.inline
    @cython.exceptval(check=False)
    def _is_in_open_state(self) -> cython.bint:
        # Before on_ws_connected, self.transport is None
        # on_ws_frame immediately send CLOSE reply on incoming CLOSE frame, so receiving CLOSE == is_close_frame_sent
        # transport.is_disconnect happens the last, asyncio Protocol got connection_lost event

        return (self.transport is not None
                and not self.transport.is_disconnected
                and not self.transport.is_close_frame_sent)

    @cython.cfunc
    @cython.inline
    def _encode_and_send(self, msg_type: WSMsgType, message: DataLike, fin: cython.bint) -> None:
        if self._permessage_deflate is not None:
            message = self._permessage_deflate.encode_frame(msg_type, message, fin)
            self.transport.send(msg_type, message, fin, msg_type != WSMsgType.CONTINUATION)
        else:
            self.transport.send(msg_type, message, fin)

    async def _wait_close_and_raise(self, exc: Optional[BaseException]=None) -> NoReturn:
        # CANCELLATION:
        # _close_fut is supposed to be set only from on_ws_disconnected.
        # It is intentionally shielded.
        await _asyncio_shield(self._close_fut)
        assert self._close_exc is not None # pacify type checker

        if exc is None:
            raise self._close_exc
        else:
            raise self._close_exc from exc

    async def _wait_send_turn(self) -> None:
        # DISCONNECT: the waiter will raise ConnectionClosed
        # It can also successfully finish, but we may be in CLOSING state.
        # In such case delegate waiting to _wait_close_and_raise

        # CANCELLATION:
        # waiter future is not shielded intentionally, it turns into Cancelled
        # state and removed from waiters by _release_send.
        # _wait_close_and_raise shields _close_fut.
        waiter: asyncio.Future[None] = self._loop.create_future()
        self._send_waiters.append(waiter)
        await waiter
        if not self._is_in_open_state():
            await self._wait_close_and_raise()

    async def _wait_write_ready(self) -> None:
        # DISCONNECT: the waiter will raise ConnectionClosed
        # It can also successfully finish, but we may be in CLOSING state.
        # In such case delegate waiting to _wait_close_and_raise

        # CANCELLATION:
        # _write_ready future is shielded intentionally. It is only supposed to
        # be set from resume_writing and on_ws_disconnected.
        assert self._write_ready is not None
        await _asyncio_shield(self._write_ready)
        if not self._is_in_open_state():
            await self._wait_close_and_raise()

    async def _get_next_async_fragment(self, async_iterator: AsyncIterator[DataLike]) -> DataLike:
        # DISCONNECT: raise ConnectionClosed if after user async interator
        # returns we are not in OPEN state

        # CANCELLATION:
        # User async iterator is also getting canceled.

        data: DataLike = await async_iterator.__anext__()
        if not self._is_in_open_state():
            await self._wait_close_and_raise()
        return data

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
    def _release_send(self) -> None:
        self._send_in_progress = False

        waiter: asyncio.Future[None]
        while self._send_waiters:
            waiter = self._send_waiters.popleft()
            # Some waiters may be canceled, that is why we have defensive check
            # for waiter.done()
            if not waiter.done():
                waiter.set_result(None)
                return

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
                    current = await self._get_next_async_fragment(async_iterator)
                else:
                    current = next(iterator)
            except stop_exception_type:
                return

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
                        current = await self._get_next_async_fragment(async_iterator)
                    else:
                        current = next(iterator)
                except stop_exception_type:
                    break

                self._check_fragment_type(current, first_is_str)
                if self._write_ready is not None:
                    await self._wait_write_ready()

            # Send the last empty frame with fin=True
            self._encode_and_send(msg_type, b"", True)
            if self._write_ready is not None:
                await self._wait_write_ready()
        except BaseException:
            self.transport.send_close(WSCloseCode.PROTOCOL_ERROR, "error in fragmented message")
            self.transport.disconnect(False)
            raise

    async def send(
        self,
        message: Union[DataLike, Iterable[DataLike], AsyncIterator[DataLike]],
        text: Optional[bool] = None,
    ) -> None:
        # send doesn't directly wait on helper futures. It is very tricky to handle
        # disconnects and cancellations properly. send delegates this to
        # _wait_* helpers.
        if not self._is_in_open_state():
            await self._wait_close_and_raise()

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
                    await self._wait_write_ready()
            # Catch a common mistake -- passing a dict to send().
            elif isinstance(message, Mapping):
                raise TypeError("data is a dict-like object")
            elif isinstance(message, (AsyncIterable, Iterable)):
                fragments: Union[AsyncIterable[DataLike], Iterable[DataLike]] = message  # type: ignore[assignment]
                await self._send_fragments(fragments, text)
            else:
                raise TypeError(f"message has unsupported type {type(message).__name__}")
        finally:
            self._release_send()

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self._send_in_progress:
            self.transport.send_close(WSCloseCode.INTERNAL_ERROR, "close during fragmented message")
            self.transport.disconnect(False)
        else:
            self.transport.send_close(cython.cast(WSCloseCode, code), reason)

        try:
            if self._close_timeout is None:
                await self.wait_closed()
            else:
                await asyncio.wait_for(self.wait_closed(), self._close_timeout)
        except asyncio.TimeoutError:
            self.transport.disconnect(False)
            await self.wait_closed()

    async def wait_closed(self) -> None:
        try:
            await self.transport.wait_disconnected()
        except Exception:
            pass

    async def ping(self, data: Optional[DataLike] = None) -> Awaitable[float]:
        if not self._is_in_open_state():
            await self._wait_close_and_raise()

        if data is None:
            while True:
                payload = os.urandom(4)
                if payload not in self._pending_pings:
                    break
        elif isinstance(data, str):
            payload = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray, memoryview)):
            payload = bytes(data)
        else:
            raise TypeError("ping payload must be str, bytes-like, or None")

        if payload in self._pending_pings:
            raise ConcurrencyError("another ping was sent with the same data")

        waiter: asyncio.Future[float] = asyncio.get_running_loop().create_future()
        self._pending_pings[payload] = (waiter, monotonic())
        self.transport.send_ping(payload)
        return waiter

    async def pong(self, data: Union[str, bytes] = b"") -> None:
        if not self._is_in_open_state():
            await self._wait_close_and_raise()

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
        if self.transport is None:
            return State.CONNECTING
        elif self.transport.is_disconnected:
            return State.CLOSED
        elif self.transport.is_close_frame_sent or self.transport.close_handshake is not None:
            return State.CLOSING
        else:
            return State.OPEN

    @property
    def request(self) -> Request:
        return self._request

    @property
    def response(self) -> Response:
        return self._response

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

    @property
    def open(self) -> bool:
        warnings.warn("Use state == State.OPEN instead", DeprecationWarning)
        return self._is_in_open_state() # type: ignore[no-any-return]

    @property
    def closed(self) -> bool:
        warnings.warn("Use state == State.CLOSED instead", DeprecationWarning)
        return self.transport is not None and self.transport.is_disconnected


@cython.cclass
class ClientConnection(ConnectionBase):
    pass


@cython.cclass
class ServerConnection(ConnectionBase):
    server: Any
    _username: Optional[str]

    def __init__(
        self,
        server: Any,
        *,
        username: Optional[str] = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self.server = server
        self._username = username

    @cython.ccall
    def on_ws_connected(self, transport: WSTransport) -> None:
        ConnectionBase.on_ws_connected(self, transport)
        self.server.loop.call_soon(self.server.start_connection_handler, self)

    @property
    def username(self) -> Optional[str]:
        return self._username


def broadcast_message(connection: ConnectionBase, msg_type: WSMsgType, message: DataLike) -> bool:
    if connection._send_in_progress:
        return False
    connection._encode_and_send(msg_type, message, True)
    return True
