"""Tests for the Z reduction, ported from ``Zreduction.test.cpp``."""

from __future__ import annotations

import pytest

from bkcrack.constants import mask
from bkcrack.keys import Keys
from bkcrack.progress import Progress, State
from bkcrack.zreduction import Zreduction


def make_keystream(length: int) -> bytes:
    keys = Keys.from_password("password")
    keystream = bytearray()
    for _ in range(length):
        keystream.append(keys.keystream_byte())
        keys.update(ord("A"))
    return bytes(keystream)


def get_z_value(index: int) -> int:
    keys = Keys.from_password("password")
    for _ in range(index):
        keys.update(ord("A"))
    return keys.z


def test_generate_only():
    keystream = make_keystream(8)
    z7 = get_z_value(7)

    zr = Zreduction(keystream)
    assert len(zr.candidates) == 2_752_512
    assert zr.index == 7
    assert (z7 & mask(10, 32)) in zr.candidates

    zr.generate()
    assert len(zr.candidates) == 4_194_304
    assert zr.index == 7
    assert (z7 & mask(2, 32)) in zr.candidates


def test_reduce_completely_and_generate():
    keystream = make_keystream(12)
    z7 = get_z_value(7)
    z11 = get_z_value(11)

    zr = Zreduction(keystream)
    assert len(zr.candidates) == 2_686_976
    assert zr.index == 11
    assert (z11 & mask(10, 32)) in zr.candidates

    progress = Progress()
    zr.reduce(progress)
    assert progress.done == 4
    assert progress.total == 4
    assert progress.state is State.NORMAL
    assert len(zr.candidates) == 898_165
    assert zr.index == 7
    assert (z7 & mask(10, 32)) in zr.candidates

    zr.generate()
    assert len(zr.candidates) == 1_368_208
    assert zr.index == 7
    assert (z7 & mask(2, 32)) in zr.candidates


@pytest.mark.slow
def test_reduce_partially_and_generate():
    keystream = make_keystream(14_336)
    z9999 = get_z_value(9999)
    z14335 = get_z_value(14_335)

    zr = Zreduction(keystream)
    assert len(zr.candidates) == 2_686_976
    assert zr.index == 14_335
    assert (z14335 & mask(10, 32)) in zr.candidates

    progress = Progress()
    zr.reduce(progress)
    assert progress.done == 5207
    assert progress.total == 14328
    assert progress.state is State.EARLY_EXIT
    assert len(zr.candidates) == 153
    assert zr.index == 9999
    assert (z9999 & mask(10, 32)) in zr.candidates

    zr.generate()
    assert len(zr.candidates) == 218
    assert zr.index == 9999
    assert (z9999 & mask(2, 32)) in zr.candidates
