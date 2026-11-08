"""Tests for password recovery, ported from ``password.test.cpp``."""

from __future__ import annotations

import pytest

from bkcrack.keys import Keys
from bkcrack.password import recover_password, recover_password_for_mask
from bkcrack.progress import Progress, State


class RecordingProgress(Progress):
    """Progress implementation which keeps every logged message."""

    def __init__(self) -> None:
        super().__init__()
        self.logs = []

    def log(self, message: str) -> None:
        self.logs.append(message)

B = tuple(range(0, 256))
P = tuple(range(0x20, 0x7F))
D = tuple(range(ord("0"), ord("9") + 1))
U = tuple(range(ord("A"), ord("Z") + 1))
L = tuple(range(ord("a"), ord("z") + 1))
A = tuple(sorted(set(L) | set(U) | set(D)))
S = tuple(sorted(set(P) - set(A)))
SL = tuple(sorted(set(S) | set(L)))


def keys_of(x: int, y: int, z: int) -> Keys:
    return Keys(x, y, z)


def test_bruteforce_empty_password():
    progress = Progress()
    result, start = recover_password(Keys(), L, 0, 8, b"", 1, False, progress)

    assert result == [b""]
    assert start == b""
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.EARLY_EXIT


def test_bruteforce_password_of_4_bytes():
    progress = Progress()
    result, start = recover_password(keys_of(0x1B226DFE, 0xC089E0A3, 0x6AF00EE6), B, 0, 4, b"", 1, False, progress)

    assert result == ["🔐".encode()]
    assert start == b""
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.EARLY_EXIT


def test_bruteforce_password_of_8_characters():
    progress = Progress()
    result, start = recover_password(keys_of(0x9BCB20C6, 0x10A97CA5, 0x103C0614), P, 0, 8, b"", 1, False, progress)

    assert result == [b"_S#cr3t!"]
    assert start == b""
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.EARLY_EXIT


@pytest.mark.slow
def test_bruteforce_password_of_10_characters():
    progress = Progress()
    result, start = recover_password(keys_of(0xEDB43A00, 0x9CE6E179, 0x8CF2CBBA), A, 0, 10, b"", 1, False, progress)

    assert result == [b"q1w2e3r4t5"]
    assert start == b"r000"
    assert progress.done == 53 * 62
    assert progress.total == 62 * 62
    assert progress.state is State.EARLY_EXIT


@pytest.mark.slow
def test_bruteforce_password_of_12_characters():
    progress = Progress()
    result, start = recover_password(keys_of(0xDCCE7593, 0xB8A2E617, 0xB2BD4365), L, 0, 12, b"", 1, False, progress)

    assert result == [b"abcdefghijkl"]
    assert start == b"abdaaa"
    assert progress.done == 0 * 26 + 1
    assert progress.total == 26 * 26
    assert progress.state is State.EARLY_EXIT


@pytest.mark.slow
def test_bruteforce_password_of_14_characters_with_restart_point():
    progress = Progress()
    result, start = recover_password(
        keys_of(0x1272EF9E, 0x20884732, 0x7A39AB85), L, 0, 14, b"mmzzzaaa", 1, False, progress
    )

    assert result == [b"mnbzzghijklmno"]
    assert start == b"mncaaaaa"
    assert progress.done == 12 * 26 + 13
    assert progress.total == 26 * 26
    assert progress.state is State.EARLY_EXIT


@pytest.mark.slow
def test_exhaustive_bruteforce():
    progress = Progress()
    result, start = recover_password(keys_of(0xEDB43A00, 0x9CE6E179, 0x8CF2CBBA), A, 0, 10, b"", 1, True, progress)

    assert result == [b"q1w2e3r4t5"]
    assert start == b""
    assert progress.done == 62 * 62
    assert progress.total == 62 * 62
    assert progress.state is State.NORMAL


def test_bruteforce_attempt_with_solution_out_of_given_charset():
    progress = RecordingProgress()
    result, start = recover_password(keys_of(0xF1F9AB49, 0x8574A6FD, 0xCB99758D), D, 0, 6, b"", 1, False, progress)

    assert result == []
    assert start == b""
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.NORMAL
    assert b"Password: 123x56 (as bytes: 31 32 33 78 35 36)" in progress.logs


def test_mask_recovery_on_empty_password():
    progress = Progress()
    result, start = recover_password_for_mask(Keys(), (), b"", 1, False, progress)

    assert result == [b""]
    assert start == b""
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.EARLY_EXIT


@pytest.mark.parametrize(
    "keys, mask, expected",
    [
        ((0x5E07E483, 0x0C4900A4, 0x4E586AC1), (U, L, D, S, (ord("."),)), b"Aa1_."),
        ((0xF9720E40, 0x2520F2B9, 0x0A5660DF), (D, L, D, L, D, L), b"1q2w3e"),
        ((0x2AF9B027, 0x85BD8154, 0x286CA64F), (L,) * 7, b"letmein"),
    ],
)
def test_mask_recovery_short_passwords(keys, mask, expected):
    progress = Progress()
    result, start = recover_password_for_mask(keys_of(*keys), mask, b"", 1, False, progress)

    assert result == [expected]
    assert start == b""
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.EARLY_EXIT


def test_mask_recovery_on_password_of_13_characters():
    mask = (L,) * 8 + ((ord("-"),),) + (D,) * 4
    progress = Progress()
    result, start = recover_password_for_mask(
        keys_of(0x0D892B8B, 0x02DD8FAD, 0x77F52C7B), mask, b"", 1, False, progress
    )

    assert result == [b"password-1234"]
    assert start == b"4400-aa"
    assert progress.done == 44
    assert progress.total == 100
    assert progress.state is State.EARLY_EXIT


def test_mask_recovery_with_restart_point():
    mask = (L,) * 8 + ((ord("-"),),) + (D,) * 4
    progress = Progress()
    result, start = recover_password_for_mask(
        keys_of(0x0D892B8B, 0x02DD8FAD, 0x77F52C7B), mask, b"4200-aa", 1, False, progress
    )

    assert result == [b"password-1234"]
    assert start == b"4400-aa"
    assert progress.done == 44
    assert progress.total == 100
    assert progress.state is State.EARLY_EXIT


def test_exhaustive_mask_recovery():
    mask = (L,) * 8 + ((ord("-"),),) + (D,) * 4
    progress = Progress()
    result, start = recover_password_for_mask(
        keys_of(0x0D892B8B, 0x02DD8FAD, 0x77F52C7B), mask, b"", 1, True, progress
    )

    assert result == [b"password-1234"]
    assert start == b""
    assert progress.done == 100
    assert progress.total == 100
    assert progress.state is State.NORMAL


def test_mask_recovery_attempt_with_solution_out_of_given_mask():
    mask = (L,) * 8 + ((ord("-"),),) + (D,) * 4
    progress = RecordingProgress()
    result, start = recover_password_for_mask(
        keys_of(0x6CF4E702, 0x193A82F5, 0x88360A9F), mask, b"", 1, False, progress
    )

    assert result == []
    assert start == b""
    assert progress.done == 100
    assert progress.total == 100
    assert progress.state is State.NORMAL
    assert (
        b"Password: passw*rd-1234 (as bytes: 70 61 73 73 77 2a 72 64 2d 31 32 33 34)" in progress.logs
    )


LOREM = b"Lorem ipsum dolor sit amet"


def test_mask_recovery_with_constant_mask():
    mask = tuple((byte,) for byte in LOREM)
    progress = Progress()
    result, start = recover_password_for_mask(
        keys_of(0xC80F5189, 0xCE16BD43, 0x38247EB5), mask, b"", 1, False, progress
    )

    assert result == [LOREM]
    assert start == b""
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.EARLY_EXIT


def test_mask_recovery_with_constant_prefix():
    mask = tuple((byte,) for byte in LOREM[:18]) + (SL,) * 8
    progress = Progress()
    result, start = recover_password_for_mask(
        keys_of(0xC80F5189, 0xCE16BD43, 0x38247EB5), mask, b"", 1, False, progress
    )

    assert result == [LOREM]
    assert start == b""
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.EARLY_EXIT


def test_mask_recovery_with_constant_suffix():
    mask = (U, SL, SL, SL, SL) + tuple((byte,) for byte in LOREM[5:])
    progress = Progress()
    result, start = recover_password_for_mask(
        keys_of(0xC80F5189, 0xCE16BD43, 0x38247EB5), mask, b"", 1, False, progress
    )

    assert result == [LOREM]
    assert start == b""
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.EARLY_EXIT


def test_mask_recovery_with_constant_prefix_and_suffix():
    mask = tuple((byte,) for byte in LOREM[:12]) + (SL,) * 9 + tuple((byte,) for byte in LOREM[21:])
    progress = Progress()
    result, start = recover_password_for_mask(
        keys_of(0xC80F5189, 0xCE16BD43, 0x38247EB5), mask, b"", 1, False, progress
    )

    assert result == [LOREM]
    assert start == b""
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.EARLY_EXIT


def test_mask_recovery_with_sparse_constant_characters():
    mask = (
        (ord("L"),), (ord("o"),), L, (ord("e"),), L, (ord(" "),), (ord("i"),), L,
        (ord("s"),), L, (ord("m"),), (ord(" "),), (ord("d"),), (ord("o"),), L, (ord("o"),),
        L, (ord(" "),), (ord("s"),), (ord("i"),), (ord("t"),), (ord(" "),), (ord("a"),), L,
        (ord("e"),), (ord("t"),),
    )

    progress = Progress()
    result, start = recover_password_for_mask(
        keys_of(0xC80F5189, 0xCE16BD43, 0x38247EB5), mask, b"", 1, False, progress
    )

    assert result == [LOREM]
    assert start == b"tena tis aoaod Loaea"
    assert progress.done == 0
    assert progress.total == 0
    assert progress.state is State.EARLY_EXIT
