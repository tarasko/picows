__version__ = "0.2.2"

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
    "picows.WSProtocol": False,
    "picows.WSFrameParser": False,
    "picows.WSFrameBuilder": False,
    "picows.MemoryBuffer": False,
    "picows.WSFrame.fin": "Indicates whether this is the last frame of the message.\n\n"
                          "Websocket messages MAY consist of multiple frames. "
                          "Unfragmented message:\n\n"
                          "    WSFrame(opcode=WSMsgType.<actual message type>, fin=True)\n"
                          "Fragmented message example:\n\n"
                          "    WSFrame(opcode=WSMsgType.<actual message type>, fin=False)\n"
                          "    WSFrame(opcode=WSMsgType.CONTINUATION, fin=False)\n"
                          "    ...\n"
                          "    # the last frame of the message\n"                          
                          "    WSFrame(opcode=WSMsgType.CONTINUATION, fin=True) \n"
                          ""
    "picows.WSFrame."

}
