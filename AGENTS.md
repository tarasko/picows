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
- In Cythonized modules, avoid `typing.cast(...)` in hot paths; use control-flow narrowing, assertions, or a narrowly
  scoped type-ignore instead. Why: `context/cython.md`.
- For `picows.websockets` work, the installed upstream `websockets` package (and its tests/docs) is the behavioral source
  of truth: verify a scenario there before changing implementation or tests. Do not update tests to match current
  `picows.websockets` behavior unless it matches upstream or a deviation has been explicitly agreed and documented.
  Why, and what "compatibility" means here: `context/websockets-compat.md`.
- If `picows` core exposes an inconsistent runtime shape or behavior that looks like a bug, do not silently normalize
  around it in wrapper code: stop and ask, or clearly call it out as a suspected core bug. Confirmed intentional quirks
  are recorded in `context/core-api.md` (the mixed bytes/str upgrade objects, send-after-close no-ops); rely on those
  instead of adding wrapper-side state.

## Why things are the way they are
- `context/index.md` lists the recorded decisions, constraints and workarounds behind the code. Read it before
  non-trivial changes, so prior decisions are not re-litigated or accidentally reverted.

## Keep the Why

This project records the reasoning behind its code with the Keep the Why
skill (https://keepthewhy.com) — the `.keep-the-why` file at the project
root is its config. Before doing anything else in a session, whatever the
first request is about, load the skill: in Claude Code, invoke the
`keep-the-why` skill (Skill tool); in Codex or any other agent, load the
installed `keep-the-why` skill (or read its `SKILL.md`) and follow it,
including the `references/*.md` files it points to for the situation at hand.

## Testing instructions
- Run lint after updating code with:
`flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics`
Fix all errors

- Run mypy after updating code with:  
`mypy picows`
Fix errors, or disable errors that seems to be mypy quirks with #ignore comments.
