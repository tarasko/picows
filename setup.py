import os
import platform
import sys
from Cython.Build import cythonize
from setuptools.command.build_ext import build_ext as _build_ext
from setuptools import Extension, setup

vi = sys.version_info
if vi < (3, 9):
    raise RuntimeError('picows requires Python 3.9 or greater')

if os.name == 'nt':
    libs = ["Ws2_32"]
else:
    libs = []


def _consume_build_ext_flag(flag: str) -> bool:
    if "build_ext" not in sys.argv:
        return False

    try:
        sys.argv.remove(flag)
    except ValueError:
        return False
    return True

with_annotate = _consume_build_ext_flag("--with-annotate")
with_debug = _consume_build_ext_flag("--with-debug")
with_examples = _consume_build_ext_flag("--with-examples")
with_coverage = _consume_build_ext_flag("--with-coverage")

dev = _consume_build_ext_flag("--dev")
if dev:
    with_annotate = True
    with_examples = True


macros = [("CYTHON_TRACE", "1"),
          ("CYTHON_TRACE_NOGIL", "1"),
          ("CYTHON_USE_SYS_MONITORING", "0")] if with_coverage else None


if os.name == 'nt' and with_debug:
    extra_compile_args = ['/Zi']
    extra_link_args = ['/DEBUG']
else:
    extra_compile_args = None
    extra_link_args = None


def _mask_compile_units():
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64", "x64"}:
        return [
            ("picows/mask_sse2.c", {"unix": ["-msse2"], "mingw32": ["-msse2"], "msvc": []}),
            ("picows/mask_avx2.c", {"unix": ["-mavx2"], "mingw32": ["-mavx2"], "msvc": ["/arch:AVX2"]}),
            ("picows/mask_avx512.c", {"unix": ["-mavx512f"], "mingw32": ["-mavx512f"], "msvc": ["/arch:AVX512"]}),
        ]

    if machine in {"i386", "i686", "x86"}:
        return [
            ("picows/mask_sse2.c", {"unix": ["-msse2"], "mingw32": ["-msse2"], "msvc": ["/arch:SSE2"]}),
            ("picows/mask_avx2.c", {"unix": ["-mavx2"], "mingw32": ["-mavx2"], "msvc": ["/arch:AVX2"]}),
            ("picows/mask_avx512.c", {"unix": ["-mavx512f"], "mingw32": ["-mavx512f"], "msvc": ["/arch:AVX512"]}),
        ]

    if machine in {"aarch64", "arm64", "armv7l", "armv8l"}:
        return [
            ("picows/mask_neon.c", {"unix": []}),
        ]

    return []


class build_ext(_build_ext):
    def build_extension(self, ext):
        compile_units = getattr(ext, "picows_extra_compile_units", None)
        if compile_units:
            self.mkpath(self.build_temp)
            extra_objects = list(ext.extra_objects or [])
            for source, flags_by_compiler in compile_units:
                extra_postargs = flags_by_compiler.get(self.compiler.compiler_type)
                if extra_postargs is None:
                    extra_postargs = flags_by_compiler.get("default")
                if extra_postargs is None:
                    continue

                objects = self.compiler.compile(
                    [source],
                    output_dir=self.build_temp,
                    macros=ext.define_macros,
                    include_dirs=ext.include_dirs,
                    debug=self.debug,
                    extra_postargs=extra_postargs,
                    depends=ext.depends,
                )
                extra_objects.extend(objects)

            ext.extra_objects = extra_objects

        super().build_extension(ext)


extensions = [
    Extension("picows.picows", ["picows/picows.pyx", "picows/mask_dispatch.c"],
              libraries=libs, define_macros=macros,
              depends=["picows/compat.h"],
              extra_compile_args=extra_compile_args,
              extra_link_args=extra_link_args),
]

if with_examples:
    extensions.append(
        Extension("examples.echo_client_cython", ["examples/echo_client_cython.pyx"],
                  libraries=libs, define_macros=macros,
                  extra_compile_args=extra_compile_args,
                  extra_link_args=extra_link_args))

cythonized_extensions = cythonize(
    extensions,
    compiler_directives={
        'language_level': vi[0],
        'freethreading_compatible': True,
        'profile': False,
        'nonecheck': False,
        'boundscheck': False,
        'wraparound': False,
        'initializedcheck': False,
        'optimize.use_switch': False,
        'cdivision': True,
        'linetrace': with_coverage
    },
    annotate=with_annotate,
    gdb_debug=with_debug,
)

for ext in cythonized_extensions:
    if ext.name == "picows.picows":
        ext.picows_extra_compile_units = _mask_compile_units()


setup(
    ext_modules=cythonized_extensions,
    cmdclass={"build_ext": build_ext},
    include_package_data=True,
)
