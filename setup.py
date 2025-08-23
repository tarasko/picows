import os
import sys
from Cython.Build import cythonize
from setuptools import Extension, setup

vi = sys.version_info
if vi < (3, 9):
    raise RuntimeError('picows requires Python 3.9 or greater')


if os.name == 'nt':
    libraries = ["Ws2_32"]
else:
    libraries = None

cython_modules = [
    Extension(
        "picows.picows",
        ["picows/picows.pyx"],
        libraries=libraries,
    )
]

if os.getenv("PICOWS_BUILD_EXAMPLES") is not None:
    cython_modules.append(
        Extension(
            "examples.echo_client_cython",
            ["examples/echo_client_cython.pyx"],
        )
    )

setup(
    ext_modules=cythonize(
        cython_modules,
        compiler_directives={
            'language_level': vi[0],
            'profile': False,
            'nonecheck': False,
            'boundscheck': False,
            'wraparound': False,
            'initializedcheck': False,
            'optimize.use_switch': False,
            'cdivision': True
        },
        annotate=False,
        gdb_debug=False
    ),
)
