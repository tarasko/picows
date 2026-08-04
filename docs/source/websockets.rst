websockets library compatibility
================================

``picows.websockets`` reimplements the common ``websockets.asyncio`` interface on
top of the picows core API. It is intended to make migration from ``websockets``
straightforward for typical client and server applications, but it doesn't
implement every extension point exposed by the original ``websockets`` package.

If you need a specific feature of the original websockets library, do not hesitate
to create a feature request.

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
* ``ServerConnection.respond()`` for building plain-text HTTP responses in
  handshake hooks. Construct and return a ``picows.websockets.Response``
  directly from synchronous ``process_request`` / ``process_response`` hooks.
* The full upstream distribution surface, including the threading, Sans-I/O, and
  legacy APIs. ``picows.websockets`` focuses on the asyncio API.
* Proxy support covers the common ``proxy=True``, ``proxy=None``, and explicit
  proxy URL cases. Advanced upstream proxy TLS keyword handling, such as
  ``proxy_ssl`` and related ``proxy_*`` options for HTTPS proxies, isn't mirrored.
  The picows core currently supports HTTP, SOCKS4, and SOCKS5 proxies, not HTTPS
  proxy URLs.
* ``ssl`` may be omitted, set to ``True`` / ``None``, or set to an
  ``ssl.SSLContext``. Passing ``ssl=False`` for ``wss://`` URIs isn't supported.
