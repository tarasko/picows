# Core API

## `WSUpgradeRequest` / `WSUpgradeResponse` keep a mixed bytes/str shape

**Type:** constraint
**Status:** active
**Evidence:** confirmed
**Source:** maintainer-written agent instructions (`AGENTS.md`, until 2026-09), moved here
**Revisit when:** an intentional breaking change of the core API is agreed

Request `method`, `path` and `version`, and response `version`, are the raw
protocol bytes; headers are decoded strings and the response `status` is an
`HTTPStatus`. That mix is public API.

**Reason:** the low-level fields are handed through as they arrive on the wire,
the header and status fields are what user code actually inspects. Users of
the core API depend on both halves as they are, so the shape is a stable
compatibility constraint, not a tidy-up candidate.

**Consequence:** neither the core nor the `picows.websockets` wrapper
normalizes this away on its own. A wrapper that needs a uniform type converts
at its own boundary (see `websockets-compat.md`) and leaves the core objects
untouched.

## Send-side calls after a CLOSE frame are no-ops

**Type:** constraint
**Status:** active
**Evidence:** confirmed
**Source:** maintainer-written agent instructions (`AGENTS.md`, until 2026-09), moved here; `WSTransport` in `picows/picows.pyx`
**Verification:** corroborated — the send paths in `picows/picows.pyx` return early once `is_close_frame_sent` or `is_disconnected` is set
**Revisit when:** the shutdown sequence of `WSTransport` changes

Once a CLOSE frame has been sent, `send()`, `send_ping()`, `send_pong()` and
a second `send_close()` do nothing. `disconnect()` and `wait_disconnected()`
are safe to call any number of times.

**Reason:** shutdown is the one place where several parties race — the peer's
close, the user's close, an error on the socket. Making the send side
idempotent in the core means every caller can just call it, instead of each
caller keeping its own "did I already close?" state.

**Consequence:** wrapper code relies on these guarantees and adds no
state-based suppression of its own around shutdown.

## `max_frame_size` applies to non-control frames only

**Type:** decision
**Status:** active
**Evidence:** inferred
**Source:** `HISTORY.rst` 2.0.0 ("Apply max_frame_size to non-control frames only"); the frame parser in `picows/picows.pyx`
**Verification:** corroborated — the parser checks control frames against 125 bytes and only data frames against `max_frame_size`; the changelog's "127" is the length-field boundary, the enforced payload limit is 125
**Revisit when:** the frame size limits are made configurable per frame type

Control frames (PING, PONG, CLOSE) are checked against the protocol's own
125-byte payload limit (the frame parser rejects a control frame above it)
and are not subject to the user-configured `max_frame_size`.

**Reason:** the setting exists to bound memory for data frames (issue #37);
control frames are bounded by the protocol already. Applying the user limit
to them would make a small `max_frame_size` reject legitimate control
traffic. The reason is inferred from the changelog wording and the code, not
stated by the maintainer.
