API reference
====================

.. automodule:: picows

.. autofunction:: ws_connect
.. autofunction:: ws_create_server

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
            WSFrame(opcode=WSMsgType.<actual message type>, fin=True)

        Fragmented message:
        ::
            WSFrame(opcode=WSMsgType.<actual message type>, fin=False)
            WSFrame(opcode=WSMsgType.CONTINUATION, fin=False)
            ...
            # the last frame of the message
            WSFrame(opcode=WSMsgType.CONTINUATION, fin=True)

    .. py:attribute:: last_in_buffer
        :type: bool

        Indicates whether this is the last available frame in the receiving buffer.
        The receiving buffer may contain more available data, but not the full frame yet.

    .. py:attribute:: tail_size
        :type: int

        Indicates how many bytes are in the receiving buffer after the current frame.


.. autoclass:: WSListener
    :members:

.. autoclass:: WSTransport

.. autoenum:: WSMsgType
.. autoenum:: WSCloseCode
