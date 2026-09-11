# `picows.websockets` compatibility layer

## Import-level compatibility with `websockets` on the client side

**Type:** decision
**Status:** active
**Evidence:** confirmed
**Source:** maintainer-written agent instructions (`AGENTS.md`, until 2026-09), moved here; `HISTORY.rst` 2.0.0
**Revisit when:** upstream `websockets` changes its public surface in a way the wrapper cannot follow

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

## Upstream `websockets` is the behavioral source of truth

**Type:** constraint
**Status:** active
**Evidence:** confirmed
**Source:** maintainer-written agent instructions (`AGENTS.md`, until 2026-09), moved here
**Revisit when:** an intentional, documented compatibility deviation is agreed

When behavior in the compatibility layer is unclear, surprising, or a test
expectation would have to change, the installed upstream `websockets`
package and its official tests and docs decide — not the current behavior of
`picows.websockets`.

**Reason:** a test updated to match the wrapper's current behavior would
lock in a deviation nobody chose. Intentional deviations exist, but each one
is agreed and documented explicitly.

## Wrapper-level workarounds for core inconsistencies are temporary and explicit

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
