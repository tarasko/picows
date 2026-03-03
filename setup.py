import os
import sys
import sysconfig
from pathlib import Path
from typing import Optional
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


def _existing_paths(paths: list[Path]) -> list[str]:
    return [str(path) for path in paths if path and path.exists()]


def _existing_path(path: Optional[Path]) -> Optional[str]:
    if path and path.exists():
        return str(path)
    return None


def _find_openssl_include_dir(prefixes: list[Path]) -> str | None:
    # Prefer direct include roots under active interpreter paths.
    candidates = []
    for prefix in prefixes:
        candidates.extend([
            prefix / "include",
            prefix / "Library" / "include",
            prefix / "opt" / "include",
        ])

    for candidate in candidates:
        if (candidate / "openssl" / "ssl.h").exists():
            return str(candidate)

    # Fallback for less standard layouts.
    for prefix in prefixes:
        if not prefix.exists():
            continue
        for match in prefix.glob("**/include/openssl/ssl.h"):
            return str(match.parent.parent)

    return None


def _find_openssl_lib_dir(prefixes: list[Path]) -> str | None:
    lib_ext = ".lib" if is_windows else (".dylib" if sys.platform == "darwin" else ".so")

    candidates = []
    for prefix in prefixes:
        candidates.extend([
            prefix / "lib",
            prefix / "lib64",
            prefix / "libs",
            prefix / "DLLs",
            prefix / "Library" / "lib",
        ])

    for candidate in candidates:
        if not candidate.exists():
            continue
        has_ssl = any(candidate.glob(f"libssl*{lib_ext}"))
        has_crypto = any(candidate.glob(f"libcrypto*{lib_ext}"))
        if has_ssl and has_crypto:
            return str(candidate)

    for prefix in prefixes:
        if not prefix.exists():
            continue
        for pattern in ("**/libssl*.dylib", "**/libssl*.so", "**/libssl*.lib"):
            for match in prefix.glob(pattern):
                candidate = match.parent
                has_ssl = any(candidate.glob("libssl*"))
                has_crypto = any(candidate.glob("libcrypto*"))
                if has_ssl and has_crypto:
                    return str(candidate)

    return None


prefixes = [
    Path(sys.prefix),
    Path(sys.base_prefix),
    Path(sys.exec_prefix),
]

openssl_root = os.environ.get("OPENSSL_ROOT_DIR")
openssl_include_env = os.environ.get("OPENSSL_INCLUDE_DIR")
openssl_lib_env = os.environ.get("OPENSSL_LIB_DIR")

python_include_dirs = _existing_paths([
    Path(sysconfig.get_config_var("INCLUDEPY") or ""),
    Path(sysconfig.get_config_var("CONFINCLUDEPY") or ""),
    Path(sysconfig.get_path("include") or ""),
    Path(sysconfig.get_path("platinclude") or ""),
])

ssl_include_dirs = list(python_include_dirs)
openssl_include = (
    _existing_path(Path(openssl_include_env)) if openssl_include_env else
    _existing_path(Path(openssl_root) / "include") if openssl_root else
    _find_openssl_include_dir(prefixes)
)
if openssl_include is not None and openssl_include not in ssl_include_dirs:
    ssl_include_dirs.append(openssl_include)

ssl_library_dirs = []
if openssl_lib_env:
    existing = _existing_path(Path(openssl_lib_env))
    if existing is not None:
        ssl_library_dirs.append(existing)
elif openssl_root:
    ssl_library_dirs.extend(_existing_paths([
        Path(openssl_root) / "lib",
        Path(openssl_root) / "lib64",
        Path(openssl_root) / "libs",
        Path(openssl_root) / "Library" / "lib",
    ]))

openssl_lib_dir = _find_openssl_lib_dir(prefixes)
if openssl_lib_dir and openssl_lib_dir not in ssl_library_dirs:
    ssl_library_dirs.append(openssl_lib_dir)

for path in _existing_paths([
    Path(sysconfig.get_config_var("LIBDIR") or ""),
    Path(sysconfig.get_config_var("LIBPL") or ""),
    Path(sys.prefix) / "lib",
    Path(sys.base_prefix) / "lib",
    Path(sys.exec_prefix) / "lib",
    Path(sys.prefix) / "libs",
    Path(sys.base_prefix) / "libs",
    Path(sys.exec_prefix) / "libs",
    Path(sys.prefix) / "DLLs",
    Path(sys.base_prefix) / "DLLs",
]):
    if path not in ssl_library_dirs:
        ssl_library_dirs.append(path)

ssl_libraries = ["libssl", "libcrypto"] if is_windows else ["ssl", "crypto"]
# ssl_include_dirs = [str(Path(sys.prefix) / "include")]
# ssl_library_dirs = [str(Path(sys.prefix) / "lib")]

pkg_extensions = [
    Extension("picows.picows", ["picows/picows.pyx"],
              libraries=base_libraries, extra_compile_args=extra_compile_args),
    Extension("aiofastnet.utils", ["aiofastnet/utils.pyx"],
              libraries=base_libraries, extra_compile_args=extra_compile_args),
    Extension("aiofastnet.transport", ["aiofastnet/transport.pyx"],
              libraries=base_libraries,
              extra_compile_args=extra_compile_args),
    Extension("aiofastnet.sslproto", sslproto_sources,
              include_dirs=ssl_include_dirs,
              library_dirs=ssl_library_dirs,
              libraries=base_libraries + ssl_libraries,
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
