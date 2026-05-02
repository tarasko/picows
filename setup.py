import os
import platform
import sys
from typing import List

from Cython.Build import cythonize
from setuptools.command.build_ext import build_ext
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


def _get_mask_compile_units() -> List[str]:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64", "x64", "i386", "i686", "x86"}:
        return ["picows/mask_sse2.c", "picows/mask_avx2.c", "picows/mask_avx512.c"]

    elif machine in {"aarch64", "arm64", "armv7l", "armv8l"}:
        return ["picows/mask_neon.c"]
    else:
        return []


def _get_extra_postargs(source: str, compiler_type: str):
    machine = platform.machine().lower()
    if "_sse2" in source:
        if compiler_type in ("unix", "mingw32"):
            return ["-msse2"]

        elif compiler_type == "msvc":
            if machine in {"i386", "i686", "x86"}:
                return ["/arch:SSE2"]
            else:
                return []
        else:
            assert False, f"attempt to compile {source} with unknown compiler type {compiler_type}"
    elif "_avx2" in source:
        if compiler_type in ("unix", "mingw32"):
            return ["-mavx2"]

        elif compiler_type == "msvc":
            return ["/arch:AVX2"]

        else:
            assert False, f"attempt to compile {source} with unknown compiler type {compiler_type}"

    elif "_avx512" in source:
        if compiler_type in ("unix", "mingw32"):
            return ["-mavx512f"]

        elif compiler_type == "msvc":
            return ["/arch:AVX512"]

        else:
            assert False, f"attempt to compile {source} with unknown compiler type {compiler_type}"
    else:
        # Other sources don't need extra-flags
        return []


class picows_build_ext(build_ext):
    """
    setuptools does not allow to specify extra compile args per source file,
    only per extension.
    We want picows.picows extensions sources to include all applicable mask_*
    files and each file should be compiled with it own arch flags. The only way
    is to hack build_ext command and compile all necessary mask_* files and
    add them to extra_objects
    """

    def build_extension(self, ext: Extension):
        if ext.name == "picows.picows":
            self.mkpath(self.build_temp)
            for source in _get_mask_compile_units():
                objects = self.compiler.compile(
                    [source],
                    output_dir=self.build_temp,
                    macros=ext.define_macros,
                    include_dirs=ext.include_dirs,
                    debug=self.debug,
                    extra_postargs=_get_extra_postargs(source, self.compiler.compiler_type),
                    depends=ext.depends,
                )
                ext.extra_objects .extend(objects)

        super().build_extension(ext)


extensions = [
    Extension("picows.picows", ["picows/picows.pyx", "picows/mask_dispatch.c"],
              libraries=libs, define_macros=macros,
              depends=["picows/compat.h"],
              extra_compile_args=extra_compile_args,
              extra_link_args=extra_link_args),
    Extension("picows.websockets.asyncio.client", ["picows/websockets/asyncio/client.py"],
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


setup(
    ext_modules=cythonize(
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
    ),
    cmdclass={"build_ext": picows_build_ext},
    include_package_data=True,
)
