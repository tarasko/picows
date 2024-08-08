import sys
from setuptools import Extension, setup
from Cython.Build import cythonize

vi = sys.version_info
if vi < (3, 8):
    raise RuntimeError('picows requires Python 3.8 or greater')

setup(
    ext_modules=cythonize([
        Extension("picows.picows", sources=["picows/picows.pyx"], extra_compile_args=[]),
        ],
        compiler_directives = {
            'language_level' : sys.version_info[0],
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
    )
)

