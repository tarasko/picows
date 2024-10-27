from enum import Enum
from ssl import SSLContext
from typing import Callable, List, Optional, Tuple

PICOWS_DEBUG_LL: int

class WSError(RuntimeError): ...

class WSMsgType(Enum):
    # websocket spec types
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
    """
    Received websocket frame.

    .. DANGER::
        Only use WSFrame object during :any:`WSListener.on_ws_frame` callback. WSFrame objects are essentially just
        pointers to the underlying receiving buffer. After :any:`WSListener.on_ws_frame` has completed the buffer
        will be reused for the new incoming data.

    In order to actually copy payload use one of the `get_*` methods.
    """

    def get_payload_as_bytes(self) -> bytes:
        """
        :return: a new bytes object with a copy of frame payload.

        This method does not cache results. Payload is copied and a new bytes object is created every time this method is called.
        """
        ...

    def get_payload_as_utf8_text(self) -> str:
        """
        :return: a new str object with a copy of frame payload.

        This method will throw if payload does not contain valid UTF8 text.

        This method does not cache results. Payload is copied and a new str object is created every time this method is called.
        """
        ...

    def get_payload_as_ascii_text(self) -> str:
        """
        :return: a new str object with a copy of frame payload.

        This method will throw if payload does not contain valid ASCII 7 text.

        This method does not cache results. Payload is copied and a new str object is created every time this method is called.
        """
        ...

    def get_payload_as_memoryview(self) -> object:
        """
        :return: continous memoryview to a parser buffer with payload.

        .. DANGER::
            Returned memoryview does NOT own the underlying memory.
            The content will be invalidated after :any:`WSListener.on_ws_frame` has completed.
            Please process payload or copy it as soon as possible.
        """
        ...

    def get_close_code(self) -> WSCloseCode:
        """
        :return: :any:`WSCloseCode`

        This method is only valid for WSMsgType.CLOSE frames.
        """
        ...

    def get_close_message(self) -> bytes:
        """
        :return: a new bytes object with a close message. If there is no close message then returns None.

        This method is only valid for WSMsgType.CLOSE frames.
        """
        ...

    def __str__(self): ...

class WSTransport:
    def __init__(self, is_client_side: bool, underlying_transport, logger, loop): ...
    def send(self, msg_type: WSMsgType, message, fin: bool = True, rsv1: bool = False):
        """
        Send a frame over websocket with a message as its payload.

        :param msg_type: :any:`WSMsgType` enum value\n
        :param message: an optional bytes-like object
        :param fin: fin bit in websocket frame.
            Indicate that the frame is the last one in the message.
        :param rsv1: first reserved bit in websocket frame.
            Some protocol extensions use it to indicate that payload
            is compressed.
        """
        ...

    def send_ping(self, message=None):
        """
        Send a PING control frame with an optional message.

        :param message: an optional bytes-like object
        """
        ...

    def send_pong(self, message=None):
        """
        Send a PONG control frame with an optional message.

        :param message: an optional bytes-like object
        """
        ...

    def send_close(
        self, close_code: WSCloseCode = WSCloseCode.NO_INFO, close_message=None
    ):
        """
        Send a CLOSE control frame with an optional message.
        This method doesn't disconnect the underlying transport.
        Does nothing if the underlying transport is already disconnected.

        :param close_code: :any:`WSCloseCode` value
        :param close_message: an optional bytes-like object
        """
        ...

    def disconnect(self, graceful: bool = True):
        """
        Close the underlying transport.

        It is safe to call this method multiple times.
        It does nothing if the transport is already closed.

        :param graceful: If True then send any remaining outgoing data in the buffer before closing the socket. This may potentially significantly delay on_ws_disconnected event since OS may wait for TCP_ACK for the data that was previously sent and until OS ack timeout fires up the socket will remain in connected state.
        """
        ...

    async def wait_disconnected(self):
        """
        Coroutine that conveniently allows to wait until websocket is
        completely disconnected.
        (underlying transport is closed, on_ws_disconnected has been called)

        """
        ...

    async def measure_roundtrip_time(self, rounds: int) -> List[float]:
        """
        Coroutine that measures roundtrip time by running ping-pong.

        :param rounds: how many ping-pong rounds to do
        :return: list of measured roundtrip times
        """
        ...

    def notify_user_specific_pong_received(self):
        """
        Notify the auto-ping loop that a user-specific pong message
        has been received.

        This method is useful when determining whether a frame contains a
        user-specific pong is too expensive for is_user_specific_pong
        (for example, it may require full JSON parsing).
        In such cases, :any:`WSListener.is_user_specific_pong` should always
        return `False`, and the logic in :any:`WSListener.on_ws_frame` should
        call :any:`WSTransport.notify_user_specific_pong_received`.

        It is safe to call this method even if auto-ping is disabled or
        the auto-ping loop doesn't expect pong messages.
        In such cases, the method simply does nothing.
        """
        ...

class WSListener:
    """
    Base class for user handlers.

    All `on_ws_*` methods receive `transport` as a first argument for convenience. It is guaranteed that passed
    `transport` object is always the same for the same connection.
    """

    def on_ws_connected(self, transport: WSTransport):
        """
        Called after websocket handshake is complete and websocket is ready to send and receive frames.
        Initiate disconnect if exception is thrown by user handler.

        :param transport: :any:`WSTransport` object
        """
        ...

    def on_ws_frame(self, transport: WSTransport, frame: WSFrame):
        """
        Called when a new frame is received.

        Initiate disconnect if exception is thrown by user handler and
        `disconnect_on_exception` was set to True in :any:`ws_connect`
        or :any:`ws_create_server`

        .. DANGER::
            WSFrame is essentially just a pointer to a chunk of memory in the receiving buffer. It does not own
            the memory. Do NOT cache or store WSFrame object for later processing because the data may be invalidated
            after :any:`WSListener.on_ws_frame` is complete.
            Process the payload immediately or just copy it with one of `WSFrame.get_*` methods.

        :param transport: :any:`WSTransport` object
        :param frame: :any:`WSFrame` object
        """
        ...

    def on_ws_disconnected(self, transport: WSTransport):
        """
        Called when websocket has been disconnected.

        :param transport: :any:`WSTransport`
        """
        ...

    def send_user_specific_ping(self, transport: WSTransport):
        """
        Called when the auto-ping logic wants to send a ping to a remote peer.

        User can override this method to send something else instead of
        the standard PING frame.

        Default implementation:

        .. code:: python

            def send_user_specific_ping(self, transport: picows.WSTransport)
                return transport.send_ping()

        :param transport: :any:`WSTransport`
        """
        ...

    def is_user_specific_pong(self, frame: WSFrame):
        """
        Called before :any:`WSListener.on_ws_frame` if auto ping is enabled and pong is expected.

        User can override this method to indicate that the received frame is a
        valid response to a previously sent user specific ping message.

        The default implementation just do:

        .. code:: python

            def is_user_specific_pong(self, frame: picows.WSFrame)
                return frame.msg_type == WSMsgType.PONG

        :return: Returns True if the frame is a response to a previously send ping. In such case the frame will be  *consumed* by the protocol, i.e :any:`WSListener.on_ws_frame` will not be called for this frame.
        """
        ...

    def pause_writing(self):
        """
        Called when the underlying transport's buffer goes over the high watermark.
        """
        ...

    def resume_writing(self):
        """
        Called when the underlying transport's buffer drains below the low watermark.
        """
        ...

class WSUpgradeRequest:
    pass

def ws_connect(
    ws_listener_factory: Callable[[], WSListener],
    url: str,
    *,
    ssl_context: Optional[SSLContext] = None,
    disconnect_on_exception: bool = True,
    websocket_handshake_timeout=5,
    logger_name: str = "client",
    enable_auto_ping: bool = False,
    auto_ping_idle_timeout: float = 10,
    auto_ping_reply_timeout: float = 10,
    auto_ping_strategy=WSAutoPingStrategy.PING_WHEN_IDLE,
    enable_auto_pong: bool = True,
    **kwargs,
) -> Tuple[WSTransport, WSListener]: ...
def ws_create_server(): ...
