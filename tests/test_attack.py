"""Tests for the attack, ported from ``Attack.test.cpp``.

These tests only exercise a handful of ``Zi[2,32)`` values so they are fast in
both the NumPy accelerated and the pure Python code paths.
"""

from __future__ import annotations

import pytest

from bkcrack.attack import attack
from bkcrack.constants import mask
from bkcrack.data import Data
from bkcrack.progress import Progress, State

PLAINTEXT = b"Hello World!"
CIPHERTEXT = bytes(
    [
        0x3E, 0xB4, 0xC5, 0x92, 0x58, 0x40, 0x9A, 0x6C, 0xED, 0x99, 0x65, 0x81,
        0x66, 0x1B, 0x1D, 0xDA, 0x5D, 0x8A, 0x8C, 0x30, 0x07, 0x76, 0x50, 0xBB,
    ]
)  # fmt: skip

EXPECTED = (0xEA9B4E4D, 0xBA789085, 0x5FF8707D)

Z7 = 0x74930E66
Z7_2_32 = [
    0x00000000,
    0x10000000,
    0x20000000,
    0x30000000,
    0x40000000,
    0x50000000,
    0x60000000,
    Z7 & mask(2, 32),
    0x80000000,
    0x90000000,
    0xA0000000,
    0xB0000000,
    0xC0000000,
    0xD0000000,
    0xE0000000,
    0xF0000000,
]

Z9 = 0x69196CEE
Z9_2_32 = [
    0x00000000,
    0x10000000,
    0x20000000,
    0x30000000,
    0x40000000,
    0x50000000,
    Z9 & mask(2, 32),
    0x70000000,
    0x80000000,
    0x90000000,
    0xA0000000,
    0xB0000000,
    0xC0000000,
    0xD0000000,
    0xE0000000,
    0xF0000000,
]


def assert_keys(solutions):
    assert len(solutions) == 1
    assert (solutions[0].x, solutions[0].y, solutions[0].z) == EXPECTED


def test_simple_case():
    data = Data(CIPHERTEXT, None, PLAINTEXT, 0, {})
    progress = Progress()

    solutions, restart = attack(data, Z7_2_32, 0, 7, 1, False, progress)

    assert_keys(solutions)
    assert restart == 8
    assert progress.done == 8
    assert progress.total == 16
    assert progress.state is State.EARLY_EXIT


def test_offset_and_extra_plaintext():
    plaintext = PLAINTEXT[2:-2]
    extra = {-2: 0x65 ^ 0x7D, -1: 0x81 ^ 0x0D, 0: ord("H"), 11: ord("!")}
    data = Data(CIPHERTEXT, None, plaintext, 2, extra)
    progress = Progress()

    solutions, restart = attack(data, Z9_2_32, 0, 7, 1, False, progress)

    assert_keys(solutions)
    assert restart == 7
    assert progress.done == 7
    assert progress.total == 16
    assert progress.state is State.EARLY_EXIT


def test_restart_point_before_solution():
    data = Data(CIPHERTEXT, None, PLAINTEXT, 0, {})
    progress = Progress()

    solutions, restart = attack(data, Z7_2_32, 4, 7, 1, False, progress)

    assert_keys(solutions)
    assert restart == 8
    assert progress.done == 8
    assert progress.total == 16
    assert progress.state is State.EARLY_EXIT


def test_restart_point_past_solution():
    data = Data(CIPHERTEXT, None, PLAINTEXT, 0, {})
    progress = Progress()

    solutions, restart = attack(data, Z7_2_32, 8, 7, 1, False, progress)

    assert solutions == []
    assert restart == 16
    assert progress.done == 16
    assert progress.total == 16
    assert progress.state is State.NORMAL


def test_exhaustive_attack():
    data = Data(CIPHERTEXT, None, PLAINTEXT, 0, {})
    progress = Progress()

    solutions, restart = attack(data, Z7_2_32, 0, 7, 1, True, progress)

    assert_keys(solutions)
    assert restart == 16
    assert progress.done == 16
    assert progress.total == 16
    assert progress.state is State.NORMAL


@pytest.mark.parametrize("jobs", [2, 4])
def test_parallel_attack_matches_sequential(jobs):
    data = Data(CIPHERTEXT, None, PLAINTEXT, 0, {})
    progress = Progress()

    solutions, restart = attack(data, Z7_2_32, 0, 7, jobs, False, progress)

    assert_keys(solutions)
    assert 0 < restart <= 16
