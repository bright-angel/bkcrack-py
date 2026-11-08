"""Tests for the cipher state, ported from ``Keys.test.cpp``."""

from __future__ import annotations

from bkcrack.keys import Keys

CIPHERTEXT = bytes([0x9A, 0x6B, 0x40, 0x2C])


def test_default_constructor():
    keys = Keys()
    assert (keys.x, keys.y, keys.z) == (0x12345678, 0x23456789, 0x34567890)


def test_construct_from_components():
    keys = Keys(0xEA9B4E4D, 0xBA789085, 0x5FF8707D)
    assert (keys.x, keys.y, keys.z) == (0xEA9B4E4D, 0xBA789085, 0x5FF8707D)


def test_construct_from_password():
    keys = Keys.from_password("password")
    assert (keys.x, keys.y, keys.z) == (0xEA9B4E4D, 0xBA789085, 0x5FF8707D)


def test_construct_from_bytes_password():
    assert Keys.from_password(b"password") == Keys.from_password("password")


def test_construct_from_empty_password():
    assert Keys.from_password("") == Keys()


def test_update_forward_with_plaintext_bytes():
    keys = Keys.from_password("password")
    for byte in b"test":
        keys.update(byte)

    assert (keys.x, keys.y, keys.z) == (0x382BD98D, 0x5AD55F3B, 0x04F8D2F6)


def test_update_forward_with_ciphertext():
    keys = Keys.from_password("password")
    keys.update_ciphertext(CIPHERTEXT, 0, 4)

    assert (keys.x, keys.y, keys.z) == (0x382BD98D, 0x5AD55F3B, 0x04F8D2F6)


def test_update_backward_with_ciphertext_bytes():
    keys = Keys(0x382BD98D, 0x5AD55F3B, 0x04F8D2F6)
    for byte in reversed(CIPHERTEXT):
        keys.update_backward(byte)

    assert (keys.x, keys.y, keys.z) == (0xEA9B4E4D, 0xBA789085, 0x5FF8707D)


def test_update_backward_with_plaintext_bytes():
    keys = Keys(0x382BD98D, 0x5AD55F3B, 0x04F8D2F6)
    for byte in reversed(b"test"):
        keys.update_backward_plaintext(byte)

    assert (keys.x, keys.y, keys.z) == (0xEA9B4E4D, 0xBA789085, 0x5FF8707D)


def test_update_backward_with_ciphertext():
    keys = Keys(0x382BD98D, 0x5AD55F3B, 0x04F8D2F6)
    keys.update_backward_ciphertext(CIPHERTEXT, 4, 0)

    assert (keys.x, keys.y, keys.z) == (0xEA9B4E4D, 0xBA789085, 0x5FF8707D)


def test_keystream_byte_matches_first_ciphertext_byte():
    keys = Keys.from_password("password")
    assert CIPHERTEXT[0] ^ keys.keystream_byte() == ord("t")


def test_str_representation():
    keys = Keys(0xEA9B4E4D, 0xBA789085, 0x5FF8707D)
    assert str(keys) == "ea9b4e4d ba789085 5ff8707d"
