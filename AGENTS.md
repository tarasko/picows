## Description

Read README.md for the basic understanding of what this project is.

picows - this is the main package.
picows.websockets - reimplements popular websockets library interface on top of picows
tests - Contains tests for picows
examples - Various examples for users on how to use picows + perf_test that could be used to build call-graph with perf 

## Code style notes
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

## Testing instructions
- Run lint after updating code with:
`flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics`
Fix all errors

- Run mypy after updating code with:  
`mypy picows`
Fix errors, or disable errors that seems to be mypy quirks with #ignore comments.
