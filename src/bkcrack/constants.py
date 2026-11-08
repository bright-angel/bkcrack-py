"""Constants and bit helpers shared by the ported algorithms.

This module mirrors ``include/bkcrack/types.hpp`` from the original C++ project.
"""

from __future__ import annotations

#: Size of the traditional PKWARE encryption header prepended to entry data.
ENCRYPTION_HEADER_SIZE = 12

#: Number of contiguous known plaintext bytes required by the attack.
CONTIGUOUS_SIZE = 8

#: Total number of known plaintext bytes required by the attack.
ATTACK_SIZE = 12

#: Multiplicative constant used in traditional PKWARE encryption.
MULT = 0x08088405

#: Multiplicative inverse of :data:`MULT` modulo 2**32.
MULT_INV = 0xD94FA8CD

#: Initial cipher state used by traditional PKWARE encryption.
DEFAULT_X = 0x12345678
DEFAULT_Y = 0x23456789
DEFAULT_Z = 0x34567890

U32 = 0xFFFFFFFF


def mask(begin: int, end: int) -> int:
    """Return a 32-bit mask keeping bits in ``[begin, end)``.

    Equivalent to the C++ ``mask<begin, end>`` template constant.
    """
    return (U32 << begin) & (U32 >> (32 - end)) & U32


def maxdiff(x: int) -> int:
    """Maximum difference between ``A`` and ``B[x, 32)`` knowing ``A = B + b``.

    Equivalent to the C++ ``maxdiff<x>`` template constant.
    """
    return mask(0, x) + 0xFF


def lsb(value: int) -> int:
    """Return the least significant byte of *value*."""
    return value & 0xFF


def msb(value: int) -> int:
    """Return the most significant byte of a 32-bit *value*."""
    return (value >> 24) & 0xFF


# Frequently used masks, precomputed for speed.
MASK_0_16 = mask(0, 16)
MASK_0_32 = mask(0, 32)
MASK_2_32 = mask(2, 32)
MASK_8_32 = mask(8, 32)
MASK_10_32 = mask(10, 32)
MASK_16_32 = mask(16, 32)
MASK_24_32 = mask(24, 32)
MASK_26_32 = mask(26, 32)

MAXDIFF_24 = maxdiff(24)
MAXDIFF_26 = maxdiff(26)
