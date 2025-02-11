import asyncio
import pathlib
import ssl

import async_timeout
import pytest

import picows

TIMEOUT = 0.5


class BinaryFrame:
    def __init__(self, frame: picows.WSFrame):
        self.msg_type = frame.msg_type
        self.payload_as_bytes = frame.get_payload_as_bytes()
        self.payload_as_bytes_from_mv = bytes(frame.get_payload_as_memoryview())
        self.fin = frame.fin
        self.rsv1 = frame.rsv1


class TextFrame:
    def __init__(self, frame: picows.WSFrame):
        self.msg_type = frame.msg_type
        self.payload_as_ascii_text = frame.get_payload_as_ascii_text()
        self.payload_as_utf8_text = frame.get_payload_as_utf8_text()
        self.fin = frame.fin
        self.rsv1 = frame.rsv1


class CloseFrame:
    def __init__(self, frame: picows.WSFrame):
        self.msg_type = frame.msg_type
        self.close_code = frame.get_close_code()
        self.close_message = frame.get_close_message()
        self.fin = frame.fin
        self.rsv1 = frame.rsv1


def materialize_frame(frame: picows.WSFrame):
    if frame.msg_type == picows.WSMsgType.TEXT:
        return TextFrame(frame)
    elif frame.msg_type == picows.WSMsgType.CLOSE:
        return CloseFrame(frame)
    else:
        return BinaryFrame(frame)


class ServerAsyncContext:
    def __init__(self, server, shutdown_timeout=TIMEOUT):
        self.server = server
        self.server_task = asyncio.create_task(server.serve_forever())
        self.plain_url = None
        self.ssl_url = None
        self.shutdown_timeout = shutdown_timeout

    async def __aenter__(self):
        await self.server.__aenter__()
        self.plain_url = f"ws://127.0.0.1:{self.server.sockets[0].getsockname()[1]}"
        self.ssl_url = f"wss://127.0.0.1:{self.server.sockets[0].getsockname()[1]}"
        return self

    async def __aexit__(self, *exc):
        self.server_task.cancel()
        await self.server.__aexit__(*exc)
        with pytest.raises(asyncio.CancelledError):
            async with async_timeout.timeout(self.shutdown_timeout):
                await self.server_task


class ClientAsyncContext:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self):
        self._transport, self._listener = await picows.ws_connect(*self.args, **self.kwargs)
        return self._transport, self._listener

    async def __aexit__(self, *exc):
        self._transport.disconnect(graceful=False)
        await self._transport.wait_disconnected()


def create_server_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(pathlib.Path(__file__).parent / "picows_test.crt",
                                pathlib.Path(__file__).parent / "picows_test.key")
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


def create_client_ssl_context():
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.hostname_checks_common_name = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context
