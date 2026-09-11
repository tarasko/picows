# Event loops and transports

## The protocol class derives from a dummy Cython type first and `asyncio.BufferedProtocol` second

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

**Type:** decision
**Status:** active
**Evidence:** inferred
**Source:** pull request #69 ("Enable buffered protocol as it is more memory efficient and faster")
**Revisit when:** a supported event loop stops implementing `BufferedProtocol`

The read path uses `asyncio.BufferedProtocol` (`get_buffer` /
`buffer_updated`) rather than the plain `data_received` callback.

**Reason:** the loop reads straight into picows' own buffer, which removes one
copy per read and the allocation of an intermediate `bytes` object. The
change was made for memory and speed; the workaround above is the price.

## `aiofastnet` is an optional dependency, and the write path trusts its copy guarantee

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
