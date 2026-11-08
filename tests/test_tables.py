"""Tests for the lookup tables and bit helpers.

Vectors are taken from the original C++ test suite (``tests/bkcrack``).
"""

from __future__ import annotations

import random

import pytest

from bkcrack.constants import lsb, mask, maxdiff, msb
from bkcrack.errors import BaseError, ArgumentsError, DataError, ZipError
from bkcrack.tables import (
    crc32,
    crc32inv,
    get_yi_24_32,
    get_zim1_10_32,
    has_zi_2_16,
    keystream_byte,
    msb_prod_fiber2,
    msb_prod_fiber3,
    zi_2_16_vector,
)


def test_crc32():
    assert crc32(0x00000000, 0x00) == 0x00000000
    assert crc32(0x12345678, 0x00) == 0x5ECCCD58
    assert crc32(0x12345678, 0x42) == 0xC61EEDE4
    assert crc32(0x12345678, 0xFF) == 0x73CE22D5
    assert crc32(0xFFFFFFFF, 0xFF) == 0x00FFFFFF


def test_crc32inv():
    assert crc32inv(0x00000000, 0x00) == 0x00000000
    assert crc32inv(0x5ECCCD58, 0x00) == 0x12345678
    assert crc32inv(0xC61EEDE4, 0x42) == 0x12345678
    assert crc32inv(0x73CE22D5, 0xFF) == 0x12345678
    assert crc32inv(0x00FFFFFF, 0xFF) == 0xFFFFFFFF


def test_get_yi_24_32():
    assert get_yi_24_32(0x00000000, 0x00000000) == 0x00000000
    assert get_yi_24_32(0x5ECCCD58, 0x12345678) == 0x00000000
    assert get_yi_24_32(0xC61EEDE4, 0x12345678) == 0x42000000
    assert get_yi_24_32(0x73CE22D5, 0x12345678) == 0xFF000000
    assert get_yi_24_32(0x00FFFFFF, 0xFFFFFFFF) == 0xFF000000


def test_get_zim1_10_32():
    assert get_zim1_10_32(0x00000000) == 0x00000000
    assert get_zim1_10_32(0x5ECCCD58) == 0x12345400
    assert get_zim1_10_32(0xC61EEDE4) == 0x12345400
    assert get_zim1_10_32(0x73CE22D5) == 0x12345400
    assert get_zim1_10_32(0x00FFFFFF) == 0xFFFFFC00


def test_compute_message_crc32():
    crc = 0xFFFFFFFF
    for byte in b"Hello World!":
        crc = crc32(crc, byte)
    crc ^= 0xFFFFFFFF

    assert crc == 0x1C291CA3


KEYS = (b"t"[0] ^ 0x9A, b"e"[0] ^ 0x6B, b"s"[0] ^ 0x40, b"t"[0] ^ 0x2C)


def test_keystream_byte():
    assert keystream_byte(0x5FF8707D) == KEYS[0]
    assert keystream_byte(0x868C2AA4) == KEYS[1]
    assert keystream_byte(0x2D8463A7) == KEYS[2]
    assert keystream_byte(0x23F4E3DC) == KEYS[3]


def test_zi_2_16_vector():
    assert zi_2_16_vector(KEYS[0], 0x7000) == (0x707C,)
    assert zi_2_16_vector(KEYS[1], 0x2800) == (0x29A8, 0x2AA4, 0x2AB0, 0x2B3C)
    assert zi_2_16_vector(KEYS[2], 0x6000) == (0x6090, 0x6184, 0x63A4)
    assert zi_2_16_vector(KEYS[3], 0xE000) == (0xE3DC,)
    assert zi_2_16_vector(KEYS[0], 0x6000) == ()


def test_has_zi_2_16_matches_vector():
    for ki in range(256):
        for zi_10_16 in range(0, 1 << 16, 1 << 10):
            assert has_zi_2_16(ki, zi_10_16) == bool(zi_2_16_vector(ki, zi_10_16))


def test_msb_prod_fiber2():
    for msbprodinv in range(256):
        fiber = msb_prod_fiber2(msbprodinv)
        for x in range(256):
            m = msb(x * 0xD94FA8CD)
            expected = m == msbprodinv or m == (msbprodinv + 255) % 256
            assert (x in fiber) == expected


def test_msb_prod_fiber3():
    for msbprodinv in range(256):
        fiber = msb_prod_fiber3(msbprodinv)
        for x in range(256):
            m = msb(x * 0xD94FA8CD)
            expected = (
                m == msbprodinv
                or m == (msbprodinv + 255) % 256
                or m == (msbprodinv + 1) % 256
            )
            assert (x in fiber) == expected


def test_bit_helpers():
    assert lsb(0x12345678) == 0x78
    assert msb(0x12345678) == 0x12

    assert mask(0, 1) == 0x00000001
    assert mask(31, 32) == 0x80000000
    assert mask(0, 8) == 0x000000FF
    assert mask(8, 16) == 0x0000FF00
    assert mask(16, 24) == 0x00FF0000
    assert mask(24, 32) == 0xFF000000
    assert mask(0, 32) == 0xFFFFFFFF


def test_maxdiff():
    generator = random.Random(0)
    for _ in range(1000):
        # keep the low byte clear so that adding any byte cannot overflow
        b = generator.getrandbits(32) & 0xFFFFFF00
        for byte in range(256):
            a = b + byte
            assert a - (b & mask(24, 32)) <= maxdiff(24)
            assert a - (b & mask(26, 32)) <= maxdiff(26)


@pytest.mark.parametrize(
    "error, expected",
    [
        (BaseError("description"), "Error: description."),
        (ArgumentsError("description"), "Arguments error: description."),
        (DataError("description"), "Data error: description."),
        (ZipError("description"), "Zip error: description."),
    ],
)
def test_error_messages(error, expected):
    assert str(error) == expected
