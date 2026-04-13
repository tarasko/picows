import os
import sys
import sysconfig
from pathlib import Path
from Cython.Build import cythonize
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


extensions = [
    Extension("picows.picows", ["picows/picows.pyx"],
              libraries=libs, define_macros=macros,
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
    include_package_data=True,
)
