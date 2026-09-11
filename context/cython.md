# Cython

## No `typing.cast(...)` in Cythonized hot paths

**Type:** constraint
**Status:** active
**Evidence:** confirmed
**Source:** maintainer-written agent instructions (`AGENTS.md`, until 2026-09), moved here
**Revisit when:** Cython starts erasing `typing.cast` at compile time

In modules that Cython compiles, `typing.cast(...)` may become a real global
lookup plus a function call on every execution instead of being erased the
way a type checker treats it.

**Reason:** the hot paths are the whole point of picows; a construct that is
free in CPython and costs a call in Cython is a silent regression.

**Rejected alternative:** casting for the type checker's benefit and accepting
the cost. Rejected — control-flow narrowing, assertions, or a narrowly scoped
`type: ignore` give the checker what it needs without touching the compiled
code.
