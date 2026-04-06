from concurrent.futures import ThreadPoolExecutor

import pytest

from picows import WSMsgType
from tests.utils import WSServer, WSClient


async def test_wrong_thread_assert():
    with ThreadPoolExecutor(max_workers=1) as executor:
        async with WSServer() as server:
            async with WSClient(server) as client:
                msg = b"ABCDEFGHIKLMNOPQ"
                msg_ba = bytearray(b"asasdfbasdfbaskjdfasd")

                with pytest.raises(RuntimeError, match="WSTransport.send called from a wrong thread"):
                    executor.submit(client.transport.send, WSMsgType.BINARY, msg).result()

                with pytest.raises(RuntimeError, match="WSTransport.send_ping called from a wrong thread"):
                    executor.submit(client.transport.send_ping).result()

                with pytest.raises(RuntimeError, match="WSTransport.send_pong called from a wrong thread"):
                    executor.submit(client.transport.send_pong).result()

                with pytest.raises(RuntimeError, match="WSTransport.send_close called from a wrong thread"):
                    executor.submit(client.transport.send_close).result()

                with pytest.raises(RuntimeError, match="WSTransport.send_reuse_external_bytearray called from a wrong thread"):
                    executor.submit(client.transport.send_reuse_external_bytearray, WSMsgType.BINARY, msg_ba, 14).result()

                with pytest.raises(RuntimeError, match="WSTransport.disconnect called from a wrong thread"):
                    executor.submit(client.transport.disconnect).result()
