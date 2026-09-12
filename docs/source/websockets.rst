websockets library compatibility
================================

``picows.websockets`` reimplements the common ``websockets.asyncio`` interface on
top of the picows core API. It is intended to make migration from ``websockets``
straightforward for typical client and server applications, but it doesn't
implement every extension point exposed by the original ``websockets`` package.

If you need a specific feature of the original websockets library, do not hesitate
to create a feature request.

Overriding the Host header
--------------------------

The hostname used for the WebSocket ``Host`` header sometimes needs to differ
from the address used as the connection destination. For example, a proxy may
need to connect to an IP address while the WebSocket server expects its public
hostname for virtual-host routing and TLS.

Unlike the original ``websockets`` package, ``picows.websockets.connect()`` can
replace the generated ``Host`` header directly through ``additional_headers``.
This avoids creating duplicate ``Host`` headers::

    from urllib.parse import urlparse

    from picows.websockets.asyncio.client import connect

    public_url = urlparse("wss://ws.example.com/socket")
    connect_url = public_url._replace(netloc="172.10.10.1").geturl()

    async with connect(
        connect_url,
        proxy="http://localhost:1080",
        server_hostname=public_url.hostname,
        additional_headers={"Host": public_url.hostname},
    ) as websocket:
        ...

Here, the proxy opens a tunnel to ``172.10.10.1``, while ``server_hostname`` uses
``ws.example.com`` for TLS SNI and certificate verification and the ``Host``
header uses it for the WebSocket upgrade request.

The following features from ``websockets`` aren't currently supported:

* Custom WebSocket extensions passed with the ``extensions`` argument to
  ``connect()`` or ``serve()``. ``permessage-deflate`` is supported through the
  standard ``compression="deflate"`` setting, and ``compression=None`` disables it.
  Other extension factories aren't accepted.
* Asynchronous ``process_request`` and ``process_response`` server hooks. Synchronous
  hooks are supported.
* Asynchronous ``basic_auth(check_credentials=...)`` callbacks. Static credentials
  and synchronous credential checks are supported.
* Custom connection classes through ``create_connection`` on ``connect()`` or
  ``serve()``.
* Unix socket helpers such as ``unix_connect()``, ``unix_serve()``, and
  ``unix_route()``.
* ``websockets.asyncio.router.route()`` and the router classes. You can route at the
  application level from ``websocket.request.path`` instead.
* The full upstream distribution surface, including the threading, Sans-I/O, and
  legacy APIs. ``picows.websockets`` focuses on the asyncio API.
* Proxy support covers the common ``proxy=True``, ``proxy=None``, and explicit
  proxy URL cases. Advanced upstream proxy TLS keyword handling, such as
  ``proxy_ssl`` and related ``proxy_*`` options for HTTPS proxies, isn't mirrored.
  The picows core supports HTTPS proxy URLs through its ``proxy_ssl_context``
  argument.
* ``ssl`` may be omitted, set to ``True`` / ``None``, or set to an
  ``ssl.SSLContext``. Passing ``ssl=False`` for ``wss://`` URIs isn't supported.
