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


def _parse_ssl_flags() -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    include_dirs: list[str] = []
    compile_args: list[str] = []
    library_dirs: list[str] = []
    libraries: list[str] = []
    link_args: list[str] = []

    cflags = sysconfig.get_config_var("MODULE__SSL_CFLAGS") or ""
    ldflags = sysconfig.get_config_var("MODULE__SSL_LDFLAGS") or ""

    for token in shlex.split(cflags):
        if token.startswith("-I"):
            include_dirs.append(token[2:])
        elif token.startswith("/I"):
            include_dirs.append(token[2:])
        else:
            compile_args.append(token)

    for token in shlex.split(ldflags):
        if token.startswith("-L"):
            library_dirs.append(token[2:])
        elif token.startswith("/LIBPATH:"):
            library_dirs.append(token[len("/LIBPATH:"):])
        elif token.startswith("-l"):
            libraries.append(token[2:])
        elif token.lower().endswith((".lib", ".a", ".so", ".dylib", ".dll")):
            link_args.append(token)
        else:
            link_args.append(token)

    include_dirs = [path for path in include_dirs if Path(path).exists()]
    library_dirs = [path for path in library_dirs if Path(path).exists()]

    def _has_openssl_headers(paths: list[str]) -> bool:
        for path in paths:
            if (Path(path) / "openssl" / "ssl.h").exists():
                return True
        return False

    if not _has_openssl_headers(include_dirs):
        openssl_includes = sysconfig.get_config_var("OPENSSL_INCLUDES") or ""
        includepy = sysconfig.get_config_var("INCLUDEPY") or ""
        confincludepy = sysconfig.get_config_var("CONFINCLUDEPY") or ""
        includedir = sysconfig.get_config_var("INCLUDEDIR") or ""

        include_candidates = [
            Path(includepy) if includepy else None,
            Path(includepy).parent if includepy else None,
            Path(confincludepy) if confincludepy else None,
            Path(confincludepy).parent if confincludepy else None,
            Path(includedir) if includedir else None,
            Path(sys.base_prefix) / "include",
            Path(sys.prefix) / "include",
            Path(sys.exec_prefix) / "include",
            Path(sys.base_prefix) / "Library" / "include",
            Path(sys.prefix) / "Library" / "include",
            Path(sys.exec_prefix) / "Library" / "include",
        ]
        include_candidates = [path for path in include_candidates if path is not None]

        for token in shlex.split(openssl_includes):
            if token.startswith("-I"):
                include_candidates.insert(0, Path(token[2:]))
            elif token:
                include_candidates.insert(0, Path(token))

        # Preserve existing include dirs (e.g. Python headers), and append OpenSSL-capable ones.
        seen = set(include_dirs)
        for candidate in include_candidates:
            if (candidate / "openssl" / "ssl.h").exists():
                candidate_str = str(candidate)
                if candidate_str not in seen:
                    include_dirs.append(candidate_str)
                    seen.add(candidate_str)

        if not _has_openssl_headers(include_dirs):
            for root in (Path(sys.base_prefix), Path(sys.prefix), Path(sys.exec_prefix)):
                if not root.exists():
                    continue
                for match in root.glob("**/include/openssl/ssl.h"):
                    candidate_str = str(match.parent.parent)
                    if candidate_str not in seen:
                        include_dirs.append(candidate_str)
                        seen.add(candidate_str)
                if _has_openssl_headers(include_dirs):
                    break

    if not library_dirs:
        lib_candidates = [
            Path(sys.base_prefix) / "lib",
            Path(sys.prefix) / "lib",
            Path(sys.exec_prefix) / "lib",
            Path(sys.base_prefix) / "libs",
            Path(sys.prefix) / "libs",
            Path(sys.exec_prefix) / "libs",
            Path(sys.base_prefix) / "DLLs",
            Path(sys.prefix) / "DLLs",
        ]
        existing = [str(path) for path in lib_candidates if path.exists()]
        library_dirs.extend(existing)

    if not libraries:
        libraries.extend(["ssl", "crypto"] if not is_windows else ["libssl", "libcrypto"])

    return include_dirs, compile_args, library_dirs, libraries, link_args


ssl_include_dirs, ssl_compile_args, ssl_library_dirs, ssl_libraries, ssl_link_args = _parse_ssl_flags()
sslproto_sources = ["aiofastnet/sslproto.pyx", "aiofastnet/static_mem_bio.c", "aiofastnet/certdecode.c"]
sslproto_libraries = base_libraries + ssl_libraries

pkg_extensions = [
    Extension("picows.picows", ["picows/picows.pyx"],
              libraries=base_libraries, extra_compile_args=extra_compile_args),
    Extension("aiofastnet.utils", ["aiofastnet/utils.pyx"],
              libraries=base_libraries, extra_compile_args=extra_compile_args),
    Extension("aiofastnet.transport", ["aiofastnet/transport.pyx"],
              libraries=base_libraries, extra_compile_args=extra_compile_args),
    Extension("aiofastnet.sslproto", sslproto_sources,
              include_dirs=ssl_include_dirs,
              library_dirs=ssl_library_dirs,
              libraries=sslproto_libraries,
              extra_compile_args=extra_compile_args + ssl_compile_args,
              extra_link_args=ssl_link_args),
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
