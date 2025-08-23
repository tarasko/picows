import os
import sys
from Cython.Build import cythonize
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

vi = sys.version_info
if vi < (3, 9):
    raise RuntimeError('picows requires Python 3.9 or greater')


# class CustomBuildExt(build_ext):
#     def build_extensions(self):
#         for ext in self.extensions:
#             if ext.extra_compile_args:
#                 ext.extra_compile_args = [
#                     flag for flag in ext.extra_compile_args if flag != '-g'
#                 ]
#             if ext.extra_link_args:
#                 ext.extra_link_args = [
#                     flag for flag in ext.extra_link_args if flag != '-g'
#                 ]
#
#             if os.name != 'nt':
#                 self.compiler.compiler_so = [
#                     flag for flag in self.compiler.compiler_so if flag != '-g'
#                 ]
#                 self.compiler.linker_so = [
#                     flag for flag in self.compiler.linker_so if flag != '-g'
#                 ]
#         super().build_extensions()
#

if os.name == 'nt':
    link_args = []
    libraries = ["Ws2_32"]
else:
    link_args = ["-Wl,-s"]
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
            extra_link_args=link_args,
        )
    )

setup(
    # cmdclass={'build_ext': CustomBuildExt},
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
