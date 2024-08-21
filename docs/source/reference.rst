API reference
====================

.. automodule:: picows

Functions
---------

.. autofunction:: ws_connect
.. autofunction:: ws_create_server

Classes
-------

.. autoclass:: WSError
    :members:

.. autoclass:: WSFrame
    :members:

    .. py:attribute:: msg_type
        :type: WSMsgType

        Message type

    .. py:attribute:: fin
        :type: bool

        Indicates whether this is the last frame of the message.
        Websocket messages MAY consist of multiple frames.

        Unfragmented message:
        ::
            WSFrame(msg_type=WSMsgType.<actual message type>, fin=True)

        Fragmented message:
        ::
            WSFrame(msg_type=WSMsgType.<actual message type>, fin=False)
            WSFrame(msg_type=WSMsgType.CONTINUATION, fin=False)
            ...
            # the last frame of the message
            WSFrame(msg_type=WSMsgType.CONTINUATION, fin=True)

    .. py:attribute:: last_in_buffer
        :type: bool

        Indicates whether this is the last available frame in the receiving buffer.
        The receiving buffer may contain more available data, but not the full frame yet.

    .. py:attribute:: tail_size
        :type: int

        Indicates how many bytes are in the receiving buffer after the current frame.

    .. py:attribute:: payload_ptr
        :type: char*

        **Available only from Cython.**

        Raw pointer to the beginning of the frame payload in the receiving buffer.

    .. py:attribute:: payload_size
        :type: size_t

        **Available only from Cython.**

        Size of the payload.

.. autoclass:: WSUpgradeRequest
    :members:

    .. py:attribute:: method
        :type: bytes

        Request method. b"GET", b"POST", etc

    .. py:attribute:: path
        :type: bytes

        Request path. For example b"/ws"

    .. py:attribute:: version
        :type: bytes

        HTTP version. For example b"HTTP/1.1"

    .. py:attribute:: headers
        :type: Dict[str, str]

        Request headers. header names are always in lowercase

.. autoclass:: WSListener
    :members:

.. autoclass:: WSTransport
    :members:

    .. py:attribute:: underlying_transport
        :type: asyncio.Transport

        Underlying TCP or SSL transport. Can be used to set buffer limits, check connection state, etc.

        **Please don't use it to send data. Use only WSTransport.send_* methods to send frames.**

    .. py:method:: send_reuse_external_buffer(WSMsgType msg_type, char* message, size_t message_size)

        **Available only from Cython.**

        Send a frame over websocket with a message as its payload.
        Don't copy message, reuse its memory and append websocket header in front of the message

        **Message's buffer should have at least 10 bytes in front of the message pointer available for writing.**

        :param msg_type: Message type
        :param message: Pointer to a message payload
        :param message_size: Size of the message payload

Enums
-----

.. autoenum:: WSMsgType
.. autoenum:: WSCloseCode
