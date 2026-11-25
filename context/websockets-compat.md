# `picows.websockets` compatibility layer

## Import-level compatibility with `websockets` on the client side

**Id:** 5c95d51c-1ddb-4c42-b23b-11619bf96f12
**Type:** decision
**Status:** active
**Evidence:** confirmed
**Source:** maintainer-written agent instructions (`AGENTS.md`, until 2026-09), moved here; `HISTORY.rst` 2.0.0
**Revisit when:** upstream `websockets` changes its public surface in a way the wrapper cannot follow
**See:** https://github.com/oliver-zehentleitner/unicorn-binance-websocket-api — acf166bd-4af3-484e-9491-738de65186eb — as of 2026-09-30

`picows.websockets` aims for a swap of the import line: type definitions,
exception definitions and other lightweight importable names exist when
upstream exposes them, even where picows has no use for them. The full server
interface and other complicated areas may be skipped.

**Reason:** the value of the package is that someone switching from
`websockets` notices as little difference as possible. Missing names break
imports before any behavior is exercised, so surface area matters more than
completeness.

**Rejected alternative:** a "spirit of websockets" API that mirrors only what
picows implements natively. Rejected — every gap is a migration blocker for
someone.

**Consequence:** a downstream client library can add picows as a second
transport by swapping `connect()` and catching a second exception family,
with no other change to its connection code; unicorn-binance-websocket-api
did exactly that (the `See` line above), and the pull requests it sent
upstream are the compatibility layer's real-world test.

## Upstream `websockets` is the behavioral source of truth

**Id:** 6ad4cf8a-2fc9-4a7f-895e-968948fb6f30
**Type:** constraint
**Status:** active
**Evidence:** confirmed
**Source:** maintainer-written agent instructions (`AGENTS.md`, until 2026-09), moved here
**Revisit when:** an intentional, documented compatibility deviation is agreed
**See:** https://github.com/oliver-zehentleitner/unicorn-binance-websocket-api — 7bed2264-1212-4c6e-a50d-857e1ca0f60d — as of 2026-09-30

When behavior in the compatibility layer is unclear, surprising, or a test
expectation would have to change, the installed upstream `websockets`
package and its official tests and docs decide — not the current behavior of
`picows.websockets`.

**Reason:** a test updated to match the wrapper's current behavior would
lock in a deviation nobody chose. Intentional deviations exist, but each one
is agreed and documented explicitly.

Issue #108 is the rule in action: `InvalidStatus.response` carried the raw
core `WSUpgradeResponse` where upstream hands out a `Response` with
`status_code`; a downstream stream thread died on the difference, and 2.2.0
fixed the wrapper rather than asking the caller to handle both shapes (the
`See` line: the downstream side of it).

## Wrapper-level workarounds for core inconsistencies are temporary and explicit

**Id:** 92b55da9-28e5-4c4c-bcfc-455736d209b6
**Type:** decision
**Status:** active
**Evidence:** confirmed
**Source:** maintainer-written agent instructions (`AGENTS.md`, until 2026-09), moved here
**Revisit when:** the wrapper accumulates more than a handful of such workarounds

When the core exposes an inconsistent runtime shape or behavior that looks
like a bug, the wrapper does not silently normalize around it. The suspected
core bug is called out; if a wrapper-level workaround is needed meanwhile it
is marked as such.

**Reason:** a workaround in the wrapper hides the bug from the core, where the
fix belongs, and turns a defect into behavior the wrapper's tests then
protect. Legitimate quirks are documented once confirmed (see
`core-api.md`); everything else is a core fix.

## 2.0.0 was a major version without breaking changes

**Id:** 89599e89-479c-40c7-bb9e-26aa6c31e965
**Type:** decision
**Status:** active
**Evidence:** confirmed
**Source:** `HISTORY.rst` 2.0.0 release notes
**Revisit when:** never — historical; listed so the version jump is not read as a hidden break

2.0.0 changed nothing for existing users of the core API. The major bump
marks the arrival of the `picows.websockets` subpackage, a drop-in
replacement for `websockets`.

**Reason:** the subpackage doubles what the project is — a second, much
larger audience gets a second API — and the version number was chosen to
signal that, not a break. The release notes say so in the first line so that
nobody holds back an upgrade.
