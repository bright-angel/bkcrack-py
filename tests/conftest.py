"""Shared fixtures and helpers for the test suite."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import List, Sequence

import pytest

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = TESTS_DIR.parent
DATA_DIR = TESTS_DIR / "data"
REFERENCE_DIR = PROJECT_DIR / "reference"
REFERENCE_BINARY = PROJECT_DIR / "_refbin" / "bkcrack-1.8.1-win64" / "bkcrack.exe"

#: Plaintext of the tutorial example (first bytes of the stored spiral.svg entry).
TUTORIAL_PLAINTEXT = b'<?xml version="1.0" '

#: Keys of the tutorial example, as recovered by the official implementation.
TUTORIAL_KEYS = (0xC4490E28, 0xB414A23D, 0x91404B31)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "crossval: needs the official bkcrack binary")


@pytest.fixture(scope="session")
def data_dir() -> Path:
    """Directory containing the zip archives used by the tests."""
    return DATA_DIR


@pytest.fixture(scope="session")
def example_archive() -> Path:
    """Path to the tutorial example archive shipped by the original project."""
    path = REFERENCE_DIR / "example" / "secrets.zip"
    if not path.is_file():
        pytest.skip("reference example archive is not available")
    return path


@pytest.fixture(scope="session")
def reference_binary() -> Path:
    """Path to the official bkcrack executable, if it is available."""
    if not REFERENCE_BINARY.is_file():
        pytest.skip("official bkcrack binary is not available")
    return REFERENCE_BINARY


def run_cli(args: Sequence[str], cwd: Path = PROJECT_DIR) -> subprocess.CompletedProcess:
    """Run ``python -m bkcrack`` in a subprocess and return the finished process."""
    return subprocess.run(
        [sys.executable, "-m", "bkcrack", *args],
        cwd=str(cwd),
        capture_output=True,
        text=False,
    )


def run_reference(binary: Path, args: Sequence[str], cwd: Path = PROJECT_DIR) -> subprocess.CompletedProcess:
    """Run the official bkcrack executable."""
    return subprocess.run(
        [str(binary), *args],
        cwd=str(cwd),
        capture_output=True,
        text=False,
    )


def extract_progress_lines(output: bytes) -> List[str]:
    """Split captured output on carriage returns to inspect progress lines."""
    text = output.decode("utf-8", "replace")
    return [line for line in text.replace("\r", "\n").splitlines()]
