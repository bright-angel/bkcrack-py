"""Tests for :mod:`bkcrack.file`."""

from __future__ import annotations

import io

import pytest

from bkcrack.errors import FileError
from bkcrack.file import load_stream, open_input, open_output


def test_open_input_missing_file(tmp_path):
    missing = tmp_path / "nope.bin"

    with pytest.raises(FileError) as excinfo:
        open_input(str(missing))

    assert excinfo.value.type_name == "File error"
    assert str(excinfo.value) == f"File error: could not open input file {missing}."


def test_open_input_is_binary(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"\x00\x01\xff")

    with open_input(str(path)) as stream:
        assert stream.read() == b"\x00\x01\xff"


def test_open_output_creates_file(tmp_path):
    path = tmp_path / "out.bin"

    with open_output(str(path)) as stream:
        stream.write(b"abc")

    assert path.read_bytes() == b"abc"


def test_open_output_on_missing_directory(tmp_path):
    target = tmp_path / "no-such-dir" / "out.bin"

    with pytest.raises(FileError) as excinfo:
        open_output(str(target))

    assert str(excinfo.value) == f"File error: could not open output file {target}."


def test_load_stream_reads_at_most_count():
    assert load_stream(io.BytesIO(b"abcdef"), 4) == b"abcd"
    assert load_stream(io.BytesIO(b"abcdef"), 100) == b"abcdef"


def test_load_stream_non_positive_count():
    assert load_stream(io.BytesIO(b"abcdef"), 0) == b""
    assert load_stream(io.BytesIO(b"abcdef"), -1) == b""
