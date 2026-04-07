import asyncio
import importlib
import os
import pathlib
import ssl
import sys
from dataclasses import dataclass
from logging import getLogger
from typing import Optional

import pytest


@pytest.fixture(autouse=True)
def coverage_only_fixture(request):
    cov_enabled = request.config.getoption("--cov", default=[])
    if cov_enabled:
        # Enable picows debug logging for coverage reports
        # Also check that all of them are well formatted
        getLogger("picows").setLevel(9)
    yield


def multiloop_event_loop_policy():
    """
    Returns a pytest fixture function named `event_loop_policy` (by assignment in the test module).

    Usage in a test module:
        from tests.utils import make_event_loop_policy_fixture
        event_loop_policy = make_event_loop_policy_fixture()

    Notes:
    - On Windows, uvloop isn't used (by default) and we return the appropriate asyncio policy.
    - On non-Windows, params are ("asyncio", "uvloop")
    """
    # Decide params at factory creation time (import-time for that module)
    uvloop = None
    winloop = None
    if os.name == "nt":
        # Winloop doesn't work with python 3.9
        if sys.version_info >= (3, 10):
            params = ("asyncio", "winloop")
        else:
            params = ("asyncio", )
        winloop = importlib.import_module("winloop")
    else:
        params = ("asyncio", "uvloop")
        uvloop = importlib.import_module("uvloop")

    @pytest.fixture(params=params)
    def event_loop_policy(request):
        name = request.param

        if name == "asyncio":
            if os.name == "nt":
                if sys.version_info >= (3, 10):
                    return asyncio.DefaultEventLoopPolicy()
                else:
                    return asyncio.WindowsSelectorEventLoopPolicy()
            else:
                return asyncio.DefaultEventLoopPolicy()
        elif name == "uvloop":
            return uvloop.EventLoopPolicy()
        elif name == "winloop":
            return winloop.EventLoopPolicy()
        else:
            raise AssertionError(f"unknown loop: {name!r}")

    return event_loop_policy


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


@dataclass
class Ssl:
    client: Optional[ssl.SSLContext] = None
    server: Optional[ssl.SSLContext] = None


@pytest.fixture(params=["tcp", "ssl"])
def ssl_context(request):
    if request.param == "ssl":
        yield Ssl(create_client_ssl_context(), create_server_ssl_context())
    else:
        yield Ssl()


@pytest.fixture(params=["native", "aiofastnet"])
def use_aiofastnet(request):
    if request.param == "native":
        yield False
    else:
        yield True


@pytest.fixture
async def loop_debug():
    asyncio.get_running_loop().set_debug(True)
