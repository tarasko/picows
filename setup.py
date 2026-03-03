import os
import shlex
import sys
import sysconfig
from pathlib import Path
from Cython.Build import cythonize
from setuptools import Extension, setup

vi = sys.version_info
if vi < (3, 9):
    raise RuntimeError('picows requires Python 3.9 or greater')


is_windows = os.name == 'nt'

if is_windows:
    base_libraries = ["Ws2_32"]
else:
    base_libraries = []

extra_compile_args = []

sslproto_sources = ["aiofastnet/sslproto.pyx", "aiofastnet/static_mem_bio.c", "aiofastnet/certdecode.c"]

cflags = sysconfig.get_config_var("MODULE__SSL_CFLAGS") or ""
ldflags = sysconfig.get_config_var("MODULE__SSL_LDFLAGS") or ""

ssl_compile_args = [x for x in cflags.split(" ") if x]
ssl_link_args = [x for x in ldflags.split(" ") if x]

pkg_extensions = [
    Extension("picows.picows", ["picows/picows.pyx"],
              libraries=base_libraries, extra_compile_args=extra_compile_args),
    Extension("aiofastnet.utils", ["aiofastnet/utils.pyx"],
              libraries=base_libraries, extra_compile_args=extra_compile_args),
    Extension("aiofastnet.transport", ["aiofastnet/transport.pyx"],
              libraries=base_libraries,
              extra_compile_args=ssl_compile_args,
              extra_link_args=ssl_link_args),
    Extension("aiofastnet.sslproto", sslproto_sources,
              extra_compile_args=extra_compile_args),
    Extension("aiofastnet.sslproto_stdlib", ["aiofastnet/sslproto_stdlib.pyx"],
              libraries=base_libraries, extra_compile_args=extra_compile_args),
]

example_extensions = [
    Extension("examples.echo_client_cython", ["examples/echo_client_cython.pyx"], libraries=base_libraries),
]

build_wheel = any(cmd in sys.argv for cmd in ("bdist_wheel",))
extensions = (pkg_extensions + example_extensions) if not build_wheel and os.name != 'nt' else pkg_extensions

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
            'cdivision': True
        },
        annotate=True,
        gdb_debug=False,
    ),
    include_package_data=True,
)
