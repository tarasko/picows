## Description

Read README.md for the basic understanding of what this project is.

picows - this is the main package.
picows.websockets - reimplements popular websockets library interface on top of picows
tests - Contains tests for picows
examples - Various examples for users on how to use picows + perf_test that could be used to build call-graph with perf 

## Code style notes
- Max line width is 120
- The project supports Python 3.9. Do not use PEP 604 union syntax
  like `A | B` in files that may be imported on Python 3.9 unless the file
  has `from __future__ import annotations`.
  Prefer `Optional[A]` / `Union[A, B]` for broad compatibility, especially in
  tests and examples where annotations are evaluated at import time.
  When changing type annotations, consider whether CI runs mypy or imports the
  file on Python 3.9.
- Do not write `del transport` or similar `del <parameter>` statements inside callbacks just to mark arguments as unused.
  Leave unused callback parameters as-is or rename them with a leading underscore if that is clearer.
  Using `del` in this situation is confusing and suggests reference-counting or lifetime management concerns.
- Prefer direct composition only when there is a real behavioral boundary.
  Do not introduce adapter / holder / deferred-event plumbing just to preserve a conceptual separation.
  If extra machinery exists only to work around the separation you introduced, the separation is probably wrong.
- Do not model impossible or non-normal internal states in the mainline code path without a concrete reason.
  If an invariant is guaranteed by control flow, write the code around that invariant instead of adding repeated defensive checks.
  Every extra "just in case" branch teaches the reader that the state is part of normal behavior.
  Add such checks only for real risks like external misuse, concurrency races, partial failure, or invariants that are genuinely hard to guarantee.
  If the only reason for the check is uncertainty in the design, fix the design first.
- When simplifying code, finish the simplification across all equivalent branches, not only at the first local site.
  If the same conversion, check, or tiny code pattern appears in multiple sibling paths after a refactor, stop and normalize it before considering the work done.
  Do not remove one layer of abstraction only to inline the same logic redundantly in several places.
  After a refactor, scan for duplicated branch bodies and duplicated type-specific handling introduced by the change.
- `picows.websockets` aims for import-level compatibility with the official `websockets` package on the client side.
  We can skip complicated areas such as the full server interface, but simple surface-area compatibility matters.
  Type definitions, exception definitions, and other lightweight importable names should exist when upstream exposes them.
  People switching from `websockets` to `picows.websockets` should notice as little difference as possible.
- For `picows.websockets` compatibility work, treat the original `websockets`
  package as the behavioral source of truth.
  When behavior is unclear, surprising, or test expectations need to change,
  first verify the same scenario against the installed upstream `websockets`
  package or its official tests/docs before changing implementation or tests.
  Do not update tests to match current `picows.websockets` behavior unless it
  has been confirmed to match upstream behavior, or unless an intentional
  compatibility deviation has been explicitly agreed and documented.
- In Cythonized Python modules, avoid `typing.cast(...)` in hot paths.
  Cython may compile `cast(...)` into a real runtime global lookup and function call instead of erasing it like a type checker would.
  Prefer control-flow narrowing, assertions, or narrowly scoped type-ignore comments when needed.
- If `picows` core exposes an inconsistent runtime shape or behavior that looks like a bug, do not silently normalize around it in wrapper code.
  Stop and ask first, or at least clearly call out that it appears to be a core bug instead of assuming it is an intentional quirk.
  Wrapper-level workarounds for such inconsistencies should be treated as temporary and explicit, not as the default resolution.
  Legitimate intentional quirks can be documented in this file separately once confirmed.
- `WSUpgradeRequest` / `WSUpgradeResponse` expose a mixed bytes/str API and this is public API.
  Request `method`, `path`, `version` and response `version` are low-level protocol bytes, while headers are decoded strings and response `status` is `HTTPStatus`.
  Do not change this shape casually in core or silently normalize it away in wrappers; treat it as a stable compatibility constraint unless an intentional breaking change is agreed.
- In `picows` core, once a CLOSE frame has been sent, later send-side API calls are effectively no-ops.
  This applies to `send_close()` as well as the other send methods.
  Also, `disconnect()` and `wait_disconnected()` are safe to call multiple times.
  Wrapper code should rely on these idempotency guarantees instead of adding its own state-based suppression around shutdown operations.

## Testing instructions
- Run lint after updating code with:
`flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics`
Fix all errors

- Run mypy after updating code with:  
`mypy picows`
Fix errors, or disable errors that seems to be mypy quirks with #ignore comments.
