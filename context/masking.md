# Masking

## One C translation unit per SIMD instruction set

**Type:** decision
**Status:** active
**Evidence:** inferred
**Source:** pull request #96 ("make separate translation unit for each architecture"); `_get_mask_compile_units()` and the per-file compile flags in `setup.py`
**Revisit when:** the build moves to a system that supports per-function target attributes portably, or a new instruction set is added

The masking kernels live in `mask_sse2.c`, `mask_avx2.c`, `mask_avx512.c`
and `mask_neon.c`, one file each, with `mask_dispatch.c` picking a kernel at
runtime from the CPU's reported features (`__builtin_cpu_supports` on
gcc/clang, `__cpuidex` on MSVC).
`setup.py` attaches the matching `-m<isa>` flag per file.

**Reason:** a compiler will only emit AVX-512 code for a unit compiled with
the AVX-512 flag, and compiling the whole extension that way would make the
binary crash on older CPUs. Separate units let each kernel be compiled for
exactly its target while the dispatcher and everything else stay baseline.
The reason is inferred from the build layout; the maintainer has not stated
it in writing.

**Rejected alternative:** a single masking file with function-level target
attributes. Not portable across the compilers and platforms picows builds
wheels for.
