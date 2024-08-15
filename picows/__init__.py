__version__ = "0.2.2"
__author__ = "Taras Kozlov"

from .picows import (
    WSMsgType,
    WSCloseCode,
    WSFrame,
    WSTransport,
    WSListener,
    ws_connect,
    ws_create_server,
    PICOWS_DEBUG_LL
)


__all__ = [
    'WSMsgType',
    'WSCloseCode',
    'WSFrame',
    'WSTransport',
    'WSListener',
    'ws_connect',
    'ws_create_server',
    'PICOWS_DEBUG_LL'
]


__pdoc__ = {
    "picows": False,
    "WSFrame.fin": "Boolean. Indicates whether this is the last frame of the message.\n\n"
                   "Websocket messages MAY consist of multiple frames. "
                   "Unfragmented message:\n\n"
                   "    WSFrame(opcode=WSMsgType.<actual message type>, fin=True)\n"
                   "Fragmented message:\n\n"
                   "    WSFrame(opcode=WSMsgType.<actual message type>, fin=False)\n"
                   "    WSFrame(opcode=WSMsgType.CONTINUATION, fin=False)\n"
                   "    ...\n"
                   "    # the last frame of the message\n"
                   "    WSFrame(opcode=WSMsgType.CONTINUATION, fin=True) \n",
    "WSFrame.last_in_buffer": "Boolean. Indicates whether this is the last available frame in the receiving "
                              "buffer. The buffer may contain more available data, but not the full frame yet.",
    "WSFrame.tail_size": "Integer. Indicates how many bytes are in the receiving buffer after the current frame.",
    "WSFrame.opcode": "`picows.WSMsgType`. The message type"
}
