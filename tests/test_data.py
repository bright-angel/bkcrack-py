"""Tests for the known plaintext normalization, ported from ``Data.test.cpp``."""

from __future__ import annotations

import pytest

from bkcrack.data import Data
from bkcrack.errors import DataError

PLAINTEXT = b"Hello World!"
CIPHERTEXT = bytes(
    [
        0x3E, 0xB4, 0xC5, 0x92, 0x58, 0x40, 0x9A, 0x6C, 0xED, 0x99, 0x65, 0x81,
        0x66, 0x1B, 0x1D, 0xDA, 0x5D, 0x8A, 0x8C, 0x30, 0x07, 0x76, 0x50, 0xBB,
    ]
)  # fmt: skip
KEYSTREAM = bytes(
    [
        0xEE, 0x96, 0x22, 0x47, 0x78, 0xB8, 0x73, 0x54, 0x4C, 0xD7, 0x7D, 0x0D,
        0x2E, 0x7E, 0x71, 0xB6, 0x32, 0xAA, 0xDB, 0x5F, 0x75, 0x1A, 0x34, 0x9A,
    ]
)  # fmt: skip


def test_contiguous_plaintext_only():
    data = Data(CIPHERTEXT, None, PLAINTEXT, 0, {})
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == PLAINTEXT
    assert data.offset == 12
    assert data.keystream == KEYSTREAM[12:24]
    assert data.extra_plaintext == ()


def test_contiguous_plaintext_and_sparse_extra_plaintext():
    data = Data(CIPHERTEXT, None, PLAINTEXT[:8], 0, {-3: 0x4E, -2: 0x18, 10: ord("d"), 11: ord("!")})
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == PLAINTEXT[:8]
    assert data.offset == 12
    assert data.keystream == KEYSTREAM[12:20]
    assert data.extra_plaintext == ((22, ord("d")), (23, ord("!")), (10, 0x18), (9, 0x4E))


def test_merge_extra_plaintext_after():
    data = Data(CIPHERTEXT, None, PLAINTEXT[:10], 0, {10: ord("d"), 11: ord("!")})
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == PLAINTEXT
    assert data.offset == 12
    assert data.keystream == KEYSTREAM[12:24]
    assert data.extra_plaintext == ()


def test_merge_extra_plaintext_before():
    data = Data(CIPHERTEXT, None, PLAINTEXT[2:12], 2, {0: ord("H"), 1: ord("e")})
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == PLAINTEXT
    assert data.offset == 12
    assert data.keystream == KEYSTREAM[12:24]
    assert data.extra_plaintext == ()


def test_overwrite_contiguous_plaintext_with_extra_plaintext():
    overwritten = bytearray(PLAINTEXT)
    overwritten[5] = ord("*")

    overwritten_keystream = bytearray(KEYSTREAM)
    overwritten_keystream[17] = CIPHERTEXT[17] ^ ord("*")

    data = Data(CIPHERTEXT, None, PLAINTEXT, 0, {5: ord("*")})
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == bytes(overwritten)
    assert data.offset == 12
    assert data.keystream == bytes(overwritten_keystream[12:24])
    assert data.extra_plaintext == ()


def test_long_contiguous_extra_plaintext_after():
    data = Data(
        CIPHERTEXT,
        None,
        bytes([0x8C]) + PLAINTEXT[:3],
        -1,
        {i: PLAINTEXT[i] for i in range(4, 12)},
    )
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == PLAINTEXT[4:12]
    assert data.offset == 16
    assert data.keystream == KEYSTREAM[16:24]
    assert data.extra_plaintext == ((14, ord("l")), (13, ord("e")), (12, ord("H")), (11, 0x8C))


def test_long_contiguous_extra_plaintext_before():
    extra = {-1: 0x8C}
    extra.update({i: PLAINTEXT[i] for i in range(0, 7)})

    data = Data(CIPHERTEXT, None, PLAINTEXT[8:12], 8, extra)
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == bytes([0x8C]) + PLAINTEXT[:7]
    assert data.offset == 11
    assert data.keystream == KEYSTREAM[11:19]
    assert data.extra_plaintext == ((20, ord("r")), (21, ord("l")), (22, ord("d")), (23, ord("!")))


def test_extra_plaintext_only():
    extra = {i: PLAINTEXT[i] for i in range(12)}
    data = Data(CIPHERTEXT, None, b"", -1, extra)
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == PLAINTEXT
    assert data.offset == 12
    assert data.keystream == KEYSTREAM[12:24]
    assert data.extra_plaintext == ()


def test_check_byte_added_to_plaintext():
    data = Data(CIPHERTEXT, 0x8C, PLAINTEXT, 0, {})
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == bytes([0x8C]) + PLAINTEXT
    assert data.offset == 11
    assert data.keystream == KEYSTREAM[11:24]
    assert data.extra_plaintext == ()


def test_check_byte_added_to_extra_plaintext():
    data = Data(CIPHERTEXT, 0x8C, PLAINTEXT[2:10], 2, {-3: 0x4E, -2: 0x18, 11: ord("!")})
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == PLAINTEXT[2:10]
    assert data.offset == 14
    assert data.keystream == KEYSTREAM[14:22]
    assert data.extra_plaintext == ((23, ord("!")), (11, 0x8C), (10, 0x18), (9, 0x4E))


def test_check_byte_overridden_by_plaintext():
    data = Data(CIPHERTEXT, 0xFF, bytes([0x8C]) + PLAINTEXT, -1, {})
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == bytes([0x8C]) + PLAINTEXT
    assert data.offset == 11
    assert data.keystream == KEYSTREAM[11:24]
    assert data.extra_plaintext == ()


def test_check_byte_overridden_by_extra_plaintext():
    data = Data(CIPHERTEXT, 0x8C, PLAINTEXT[2:12], 2, {-2: 0x18, -1: 0xFF})
    assert data.ciphertext == CIPHERTEXT
    assert data.plaintext == PLAINTEXT[2:12]
    assert data.offset == 14
    assert data.keystream == KEYSTREAM[14:24]
    assert data.extra_plaintext == ((11, 0xFF), (10, 0x18))


@pytest.mark.parametrize(
    "ciphertext, plaintext, offset, extra, message",
    [
        (CIPHERTEXT[:11], PLAINTEXT[:11], -12, {}, "ciphertext is too small for an attack (minimum length is 12)"),
        (CIPHERTEXT[:12], b"A" * 13, -12, {}, "ciphertext is smaller than plaintext"),
        (CIPHERTEXT, PLAINTEXT[:7], 0, {}, "not enough contiguous plaintext (7 bytes available, minimum is 8)"),
        (
            CIPHERTEXT,
            PLAINTEXT[:9],
            0,
            {10: ord("d"), 11: ord("!")},
            "not enough plaintext (11 bytes available, minimum is 12)",
        ),
    ],
)
def test_not_enough_data(ciphertext, plaintext, offset, extra, message):
    with pytest.raises(DataError) as info:
        Data(ciphertext, None, plaintext, offset, extra)
    assert message in str(info.value)


@pytest.mark.parametrize(
    "plaintext, offset, extra, message",
    [
        (PLAINTEXT, -13, {}, "plaintext offset -13 is too small (minimum is -12)"),
        (PLAINTEXT, 1, {}, "plaintext offset 1 is too large"),
        (PLAINTEXT, 0, {-13: 0x00}, "extra plaintext offset -13 is too small (minimum is -12)"),
        (PLAINTEXT, 0, {12: 0x00}, "extra plaintext offset 12 is too large"),
    ],
)
def test_invalid_offset(plaintext, offset, extra, message):
    with pytest.raises(DataError) as info:
        Data(CIPHERTEXT, None, plaintext, offset, extra)
    assert message in str(info.value)
