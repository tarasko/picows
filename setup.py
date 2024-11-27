import sys
import os
from setuptools import Extension, setup
from Cython.Build import cythonize

vi = sys.version_info
if vi < (3, 8):
    raise RuntimeError('picows requires Python 3.8 or greater')

if os.name == 'nt':
    libraries = ["Ws2_32"]
else:
    libraries = None

cython_modules = [
    Extension("picows.picows", ["picows/picows.pyx"], libraries=libraries)
    ]

if os.getenv("PICOWS_BUILD_EXAMPLES") is not None:
    cython_modules.append(Extension("examples.echo_client_cython", ["examples/echo_client_cython.pyx"]))

setup(
    ext_modules=cythonize(
        cython_modules,
        compiler_directives={
            'language_level': sys.version_info[0],
            'profile': False,
            'nonecheck': False,
            'boundscheck': False,
            'wraparound': False,
            'initializedcheck': False,
            'optimize.use_switch': False,
            'cdivision': True
        },
        annotate=True,
        gdb_debug=False
    ),
)
