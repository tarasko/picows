from pathlib import Path

import pytest


def _is_codspeed_enabled(config: pytest.Config) -> bool:
    try:
        return bool(config.getoption("codspeed"))
    except ValueError:
        return False


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "codspeed: marks tests that are only collected with --codspeed",
    )


def pytest_ignore_collect(
    collection_path: Path,
    config: pytest.Config,
) -> bool:
    return (
        collection_path.name == "test_benchmarks.py"
        and not _is_codspeed_enabled(config)
    )
