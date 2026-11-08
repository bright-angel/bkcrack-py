"""File helpers mirroring ``file.cpp``."""

from __future__ import annotations

from typing import BinaryIO

from .errors import FileError

__all__ = ["open_input", "open_output", "load_stream"]


def open_input(filename: str) -> BinaryIO:
    """Open *filename* for binary reading.

    Raises :class:`FileError` if the file cannot be opened, like the original
    implementation does.
    """
    try:
        return open(filename, "rb")
    except OSError:
        raise FileError(f"could not open input file {filename}") from None


def open_output(filename: str) -> BinaryIO:
    """Create *filename* for binary writing, raising :class:`FileError` on failure."""
    try:
        return open(filename, "wb")
    except OSError:
        raise FileError(f"could not open output file {filename}") from None


def load_stream(stream: BinaryIO, count: int) -> bytes:
    """Read at most *count* bytes from *stream*."""
    if count <= 0:
        return b""
    if count >= (1 << 31):
        return stream.read()
    return stream.read(count)
