# Event loops and transports

## The protocol class derives from a dummy Cython type first and `asyncio.BufferedProtocol` second

**Id:** 4aaa0f70-0611-4c01-aa0d-90580a89ba08
**Type:** workaround
**Status:** active
**Evidence:** confirmed
**Source:** maintainer comment above the protocol class in `picows/picows.pyx`
**Revisit when:** Cython allows a pure-Python first base for extension types, or uvloop and asyncio agree on how they detect a buffered protocol

uvloop and asyncio detect a `BufferedProtocol` differently: uvloop looks for a
`get_buffer` attribute on a type that does not derive from `asyncio.Protocol`,
asyncio requires actual inheritance from `asyncio.BufferedProtocol`. Cython
extension types cannot take a pure-Python class as their first base.

**Reason:** deriving from a dummy Cython type first and
`asyncio.BufferedProtocol` second satisfies both loops with one class.

**Consequence:** on Windows the default `ProactorEventLoop` does not
genuinely use the buffered protocol — it reads into its own buffer and copies
into the user's — so the zero-copy read path only pays off there with the
selector loop. The recommendation to switch a Windows client to
`WindowsSelectorEventLoopPolicy` lives in the same code comment; it is not
yet in `docs/`.

## Buffered protocol instead of `data_received`

**Id:** c55efb4d-d6c0-4110-b68e-56b8307f53aa
**Type:** decision
**Status:** active
**Evidence:** inferred
**Source:** pull request #69 ("Enable buffered protocol as it is more memory efficient and faster")
**Revisit when:** a supported event loop stops implementing `BufferedProtocol`
**See:** event-loops.md#the-protocol-class-derives-from-a-dummy-cython-type-first-and-asynciobufferedprotocol-second — 4aaa0f70-0611-4c01-aa0d-90580a89ba08 — as of 2026-09-30

The read path uses `asyncio.BufferedProtocol` (`get_buffer` /
`buffer_updated`) rather than the plain `data_received` callback.

**Reason:** the loop reads straight into picows' own buffer, which removes one
copy per read and the allocation of an intermediate `bytes` object. The
change was made for memory and speed; the workaround above is the price.

## Reads from the socket can be capped per call (`max_read_size`)

**Id:** 0dfae98e-3584-46ed-86cc-d5207eb3f66b
**Type:** decision
**Status:** open
**Evidence:** confirmed
**Source:** issue #117, pull request #118 (measurements in its description); the unicorn-binance-websocket-api replay benchmark that surfaced it
**Revisit when:** #118 is merged (record the chosen default here) or rejected
**See:** https://github.com/oliver-zehentleitner/unicorn-binance-websocket-api — b8a65cf6-d48b-42dd-8924-e5682ba6f947 — as of 2026-09-30
**See:** https://github.com/oliver-zehentleitner/unicorn-binance-websocket-api — 2be4c0ef-a914-4ae8-880c-6e2c56473864 — as of 2026-09-30

`get_buffer()` hands the transport the whole free part of the read buffer.
When the peer is faster than the consumer, the kernel receive buffer holds
megabytes and one read pulls all of it in; the buffer doubles to fit and
never shrinks, and the frames are then copied out and decoded after their
bytes have left the CPU cache. On 450 KB frames from a loopback firehose
this made picows slower per message than the pure-Python `websockets`
library, whose asyncio transport reads 256 KB at a time (strace: 79 reads
of ~3.4 MB versus 1,060 reads of 256 KB for the same 600 messages).

**Decision proposed in #118:** a `max_read_size` argument on `ws_connect()`
and `ws_create_server()`, applied in `get_buffer()` as an upper bound on
the bytes offered per read, default `0` = unchanged. With 256 KB the same
scenario went from 3,780 to 8,381 msgs/s (297 to 146 µs CPU per message);
the echo case with a fast consumer does not change.

**Rejected alternative:** a larger `read_buffer_init_size`. A 4 MiB
initial buffer measured the same as the 16 KB default (313 vs. 229 µs
against websockets), so the doubling is not where the time goes; it
happens a few times per connection, the per-byte cost is in every read.

**Open:** whether the default should be a cap in the range of the asyncio
transport's 256 KB instead of `0`; that is the maintainer's call and is
asked in #118.

The consumer-side half of the same finding lives in the project that
surfaced it: its stream loop scanned every payload in full for endpoint
markers, which is what made the consumer slower than the wire; that scan is
now confined to the message head (first `See` line: the benchmark and its
reading, second: that fix).

## `aiofastnet` is an optional dependency, and the write path trusts its copy guarantee

**Id:** 36e0f3f5-8050-45de-ae0e-20ce5d14684a
**Type:** decision
**Status:** active
**Evidence:** confirmed
**Source:** `README.md` (aiofastnet bullet); maintainer comment in the write path of `picows/picows.pyx`; pull request #89
**Revisit when:** aiofastnet changes its write semantics, or the transport gains another fast path

`aiofastnet` is not required; when it provides the transport, picows hands
the write path a non-owning memoryview into its own buffer instead of
building a `bytes` object.

**Reason:** aiofastnet guarantees that data it cannot send immediately is
copied, so the view can point at memory picows will reuse. The stock asyncio
transport makes no such promise, which is why that branch still allocates.
Keeping the dependency optional lets picows run on any loop; the fast path is
a bonus where the guarantee holds.
