"""Lookup tables used by the attack.

This module mirrors ``Crc32Tab``, ``KeystreamTab`` and ``MultTab`` from the C++
project.  Every table is built once at import time, exactly like the static
``instance`` objects of the original code.
"""

from __future__ import annotations

from typing import List, Tuple

from .constants import (
    MASK_0_16,
    MASK_10_32,
    MULT_INV,
    U32,
)

__all__ = [
    "CRC_TABLE",
    "CRC_INV_TABLE",
    "KEYSTREAM_TABLE",
    "KEYSTREAM_INV",
    "KEYSTREAM_EXISTS",
    "MSB_PROD_FIBER2",
    "MSB_PROD_FIBER3",
    "crc32",
    "crc32inv",
    "get_yi_24_32",
    "get_zim1_10_32",
    "keystream_byte",
    "zi_2_16_vector",
    "has_zi_2_16",
    "msb_prod_fiber2",
    "msb_prod_fiber3",
]


def _build_crc32_tables() -> Tuple[List[int], List[int]]:
    """Build the CRC32 and inverse CRC32 lookup tables.

    Port of ``Crc32Tab::Crc32Tab``.  The inverse table maps the most significant
    byte of a CRC value back to ``(crc << 8) ^ b``.
    """
    crc_polynom = 0xEDB88320

    crctab = [0] * 256
    crcinvtab = [0] * 256

    for b in range(256):
        crc = b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ crc_polynom
            else:
                crc >>= 1

        crctab[b] = crc
        crcinvtab[crc >> 24] = ((crc << 8) & U32) ^ b

    return crctab, crcinvtab


CRC_TABLE, CRC_INV_TABLE = _build_crc32_tables()


def _build_keystream_tables() -> Tuple[bytearray, List[List[Tuple[int, ...]]], List[int]]:
    """Build the keystream byte table and its inverse filter tables.

    Port of ``KeystreamTab::KeystreamTab``.  ``z_2_16`` iterates over the 16-bit
    values congruent to 0 modulo 4; only ``Z[2,16)`` influences the keystream.
    """
    keystreamtab = bytearray(1 << 14)
    keystreaminvfiltertab: List[List[list]] = [[[] for _ in range(64)] for _ in range(256)]
    keystreaminvexists = [0] * 256

    for z_2_16 in range(0, 1 << 16, 4):
        k = (((z_2_16 | 2) * (z_2_16 | 3)) >> 8) & 0xFF

        keystreamtab[z_2_16 >> 2] = k
        keystreaminvfiltertab[k][z_2_16 >> 10].append(z_2_16)
        keystreaminvexists[k] |= 1 << (z_2_16 >> 10)

    return (
        keystreamtab,
        [[tuple(v) for v in per_byte] for per_byte in keystreaminvfiltertab],
        keystreaminvexists,
    )


KEYSTREAM_TABLE, KEYSTREAM_INV, KEYSTREAM_EXISTS = _build_keystream_tables()


def _build_mult_tables() -> Tuple[List[Tuple[int, ...]], List[Tuple[int, ...]]]:
    """Build the multiplication fiber tables.

    Port of ``MultTab::MultTab``.  ``fiber2`` lists the bytes ``x`` such that
    ``msb(x * MULT_INV)`` is ``msbprod`` or ``msbprod - 1``; ``fiber3`` also
    includes ``msbprod + 1``.
    """
    msbprodfiber2: List[list] = [[] for _ in range(256)]
    msbprodfiber3: List[list] = [[] for _ in range(256)]

    prodinv = 0
    for x in range(256):
        m = prodinv >> 24
        msbprodfiber2[m].append(x)
        msbprodfiber2[(m + 1) % 256].append(x)

        msbprodfiber3[(m + 255) % 256].append(x)
        msbprodfiber3[m].append(x)
        msbprodfiber3[(m + 1) % 256].append(x)

        prodinv = (prodinv + MULT_INV) & U32

    return (
        [tuple(v) for v in msbprodfiber2],
        [tuple(v) for v in msbprodfiber3],
    )


MSB_PROD_FIBER2, MSB_PROD_FIBER3 = _build_mult_tables()


def crc32(pval: int, b: int) -> int:
    """Return ``CRC32(pval, b)`` using the lookup table."""
    return (pval >> 8) ^ CRC_TABLE[(pval & 0xFF) ^ b]


def crc32inv(crc: int, b: int) -> int:
    """Return ``CRC32^-1(crc, b)`` using the lookup table."""
    return (((crc << 8) & U32) ^ CRC_INV_TABLE[crc >> 24]) ^ b


def get_yi_24_32(zi: int, zim1: int) -> int:
    """Return ``Yi[24,32)`` from ``Zi`` and ``Z{i-1}`` using ``CRC32^-1``."""
    return ((crc32inv(zi, 0) ^ zim1) << 24) & U32


def get_zim1_10_32(zi_2_32: int) -> int:
    """Return ``Z{i-1}[10,32)`` from ``Zi[2,32)`` using ``CRC32^-1``."""
    return crc32inv(zi_2_32, 0) & MASK_10_32


def keystream_byte(zi: int) -> int:
    """Return the keystream byte associated with ``Zi`` (only ``Zi[2,16)`` is used)."""
    return KEYSTREAM_TABLE[(zi & MASK_0_16) >> 2]


def zi_2_16_vector(ki: int, zi_10_16: int) -> Tuple[int, ...]:
    """Return ``Zi[2,16)`` values having the given ``[10,16)`` bits.

    Every returned value ``zi`` satisfies ``keystream_byte(zi) == ki``.
    """
    return KEYSTREAM_INV[ki][(zi_10_16 & MASK_0_16) >> 10]


def has_zi_2_16(ki: int, zi_10_16: int) -> bool:
    """Return whether :func:`zi_2_16_vector` would return a non-empty sequence."""
    return bool(KEYSTREAM_EXISTS[ki] & (1 << ((zi_10_16 & MASK_0_16) >> 10)))


def msb_prod_fiber2(msbprodinv: int) -> Tuple[int, ...]:
    """Return bytes ``x`` such that ``msb(x * MULT_INV)`` is ``msbprodinv`` or ``msbprodinv - 1``."""
    return MSB_PROD_FIBER2[msbprodinv]


def msb_prod_fiber3(msbprodinv: int) -> Tuple[int, ...]:
    """Return bytes ``x`` such that ``msb(x * MULT_INV)`` is ``msbprodinv``, -1 or +1."""
    return MSB_PROD_FIBER3[msbprodinv]
