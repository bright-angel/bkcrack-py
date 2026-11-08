"""Vectorized exploration of the Y lists for one complete Z list.

A complete Z list (``Z0`` to ``Z7``) leaves 65536 candidate ``Y7[8,24)`` values to
explore.  Each of them leads to a chain of ``Y6``, ``Y5``, ``Y4`` and ``Y3``
values, ending with the X-list consistency test, which in turn lets about a
quarter of the candidates through.  Doing all this in pure Python is about two
orders of magnitude slower than the reference C++ implementation, so this module
performs the same computation with NumPy, including the first byte of the
forward deciphering check.

The enumeration is equivalent to the reference recursive code: same filters and
same values.  Only the order in which sibling branches that both survive are
visited may differ; the set of solutions is identical.

All intermediate values are kept in ``uint32`` arrays so that arithmetic wraps
modulo 2**32, exactly like the unsigned 32-bit arithmetic of the C++ code.
"""

from __future__ import annotations

from typing import List, Tuple

import numpy as np

from .constants import (
    MASK_24_32,
    MASK_26_32,
    MASK_8_32,
    MAXDIFF_24,
    MAXDIFF_26,
    MULT,
    MULT_INV,
)
from .tables import (
    CRC_INV_TABLE,
    CRC_TABLE,
    KEYSTREAM_TABLE,
    MSB_PROD_FIBER2,
    MSB_PROD_FIBER3,
    get_yi_24_32,
)

#: Number of ``Y7[8,24)`` values enumerated per complete Z list.
BLOCK = 1 << 16

_STEP = np.uint32((MULT_INV << 8) & 0xFFFFFFFF)
_MULT_INV_32 = np.uint32(MULT_INV)
_MULT_32 = np.uint32(MULT)
_MAXDIFF_24 = np.uint32(MAXDIFF_24)
_MAXDIFF_26 = np.uint32(MAXDIFF_26)
_MASK_8_32 = np.uint32(MASK_8_32)

_K_RANGE = (np.arange(BLOCK, dtype=np.uint32) * _STEP)

_CRC = np.array(CRC_TABLE, dtype=np.uint32)
_CRCINV = np.array(CRC_INV_TABLE, dtype=np.uint32)
_KS = np.array(KEYSTREAM_TABLE, dtype=np.uint32)

_SENTINEL = 256


def _fiber_matrix(fiber, width: int) -> np.ndarray:
    """Build a ``(256, width)`` array of fiber values padded with 256."""
    matrix = np.full((256, width), _SENTINEL, dtype=np.uint32)
    for index, values in enumerate(fiber):
        matrix[index, : len(values)] = values
    return matrix


F3_WIDTH = max(len(values) for values in MSB_PROD_FIBER3)
F2_WIDTH = max(len(values) for values in MSB_PROD_FIBER2)

_F3 = _fiber_matrix(MSB_PROD_FIBER3, F3_WIDTH)
_F2 = _fiber_matrix(MSB_PROD_FIBER2, F2_WIDTH)


def _crc32_vec(pval: np.ndarray, b: int) -> np.ndarray:
    """Vectorized ``crc32``."""
    return (pval >> np.uint32(8)) ^ _CRC[((pval & np.uint32(0xFF)) ^ np.uint32(b)).astype(np.intp)]


def _crc32inv_vec(crc: np.ndarray, b: int) -> np.ndarray:
    """Vectorized ``crc32inv``."""
    return (
        (crc << np.uint32(8)) ^ _CRCINV[(crc >> np.uint32(24)).astype(np.intp)]
    ) ^ np.uint32(b)


def _crc32_scalar_msb(z: int, msb_bytes: np.ndarray) -> np.ndarray:
    """Vectorized ``crc32(z, b)`` for a constant ``z`` and an array of bytes."""
    return (np.uint32(z >> 8)) ^ _CRC[
        ((np.uint32(z & 0xFF)) ^ msb_bytes).astype(np.intp)
    ]


def _level7(ylist: List[int]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Enumerate ``Y7[8,24)`` and derive ``Y6`` and ``X7[0,8)``.

    Returns arrays ``(y7, y6, x7_low)`` in iteration order.  This inlines
    ``exploreYlists(7)``.
    """
    y7 = ylist[7]
    y5_24_32 = np.uint32(ylist[5] & MASK_24_32)
    y6_24_32 = np.uint32(ylist[6] & MASK_24_32)
    y6_msb = ylist[6] >> 24
    y7_top = np.uint32(ylist[7] & MASK_24_32)

    # prod == (Y7[8,32) - 1) * mult^-1 for each Y7[8,24) value
    base = np.uint32((((MULT_INV * (y7 >> 24)) << 24) - MULT_INV) & 0xFFFFFFFF)
    prod = base + _K_RANGE
    index = ((np.uint32(y6_msb) - (prod >> np.uint32(24))) & np.uint32(0xFF)).astype(np.intp)

    # possible Y7[0,8) values, filtered with Y6[24,32)
    y0_all = _F3[index]
    contribution = (prod[:, None] + _MULT_INV_32 * y0_all - y6_24_32) <= _MAXDIFF_24
    keep = (y0_all < _SENTINEL) & contribution

    k_index, _slot = np.nonzero(keep)
    y0 = y0_all[k_index, _slot]

    y7_full = y0 | (k_index.astype(np.uint32) << np.uint32(8)) | y7_top

    # inlined exploreYlists(7): derive Y6 and X7[0,8)
    fy = (y7_full - np.uint32(1)) * _MULT_INV_32
    ffy = (fy - np.uint32(1)) * _MULT_INV_32
    index2 = ((ffy - y5_24_32) >> np.uint32(24)).astype(np.intp)

    xi_all = _F2[index2]
    yim1_all = fy[:, None] - xi_all

    keep2 = xi_all < _SENTINEL
    keep2 &= (yim1_all >> np.uint32(24)) == np.uint32(y6_msb)
    keep2 &= (ffy[:, None] - _MULT_INV_32 * xi_all - y5_24_32) <= _MAXDIFF_24

    rows, slots2 = np.nonzero(keep2)

    return (
        y7_full[rows],
        yim1_all[rows, slots2],
        xi_all[rows, slots2],
    )


def _expand(
    y_cur: np.ndarray, y_i2_24_32: int, y_prev_msb: int
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Expand one Y level with ``exploreYlists(i)`` for ``i`` in 6, 5, 4.

    Returns ``(y_next, x_low, parent_index)`` where ``parent_index`` maps each
    child back to its parent in *y_cur*.
    """
    fy = (y_cur - np.uint32(1)) * _MULT_INV_32
    ffy = (fy - np.uint32(1)) * _MULT_INV_32

    y_i2 = np.uint32(y_i2_24_32)
    index = ((ffy - y_i2) >> np.uint32(24)).astype(np.intp)

    xi_all = _F2[index]
    yim1_all = fy[:, None] - xi_all

    keep = xi_all < _SENTINEL
    keep &= (yim1_all >> np.uint32(24)) == np.uint32(y_prev_msb)
    keep &= (ffy[:, None] - _MULT_INV_32 * xi_all - y_i2) <= _MAXDIFF_24

    rows, slots = np.nonzero(keep)

    return yim1_all[rows, slots], xi_all[rows, slots], rows


def explore_leaf(
    zlist: List[int],
    ylist: List[int],
    keystream: bytes,
    index: int,
    plaintext: bytes,
    ciphertext: bytes,
    offset: int,
) -> List[Tuple[int, int, int, int]]:
    """Explore every Y list compatible with one complete Z list.

    Returns the ``(X7, Y7, X3, Y3)`` states passing the X3 consistency test and
    the first byte of the forward deciphering check.  They must then be fully
    verified against the remaining plaintext.
    """
    y7_arr, y6_arr, x7_arr = _level7(ylist)
    if y7_arr.size == 0:
        return []

    # levels 6, 5 and 4 of the Y lists
    y5_arr, x6_arr, p6 = _expand(y6_arr, ylist[4] & MASK_24_32, ylist[5] >> 24)
    if y5_arr.size == 0:
        return []

    y4_arr, x5_arr, p5 = _expand(y5_arr, ylist[3] & MASK_24_32, ylist[4] >> 24)
    if y4_arr.size == 0:
        return []

    y3_arr, x4_arr, p4 = _expand(y4_arr, ylist[2] & MASK_24_32, ylist[3] >> 24)
    if y3_arr.size == 0:
        return []

    # gather the low bytes of X5, X6, X7 and the Y7 value of every Y-tree leaf
    x5_low = x5_arr[p4]
    x6_low = x6_arr[p5][p4]
    x7_low = x7_arr[p6][p5][p4]
    y7_sel = y7_arr[p6][p5][p4]

    # compute X5, X6 and X7 from X4 and the known plaintext
    x5 = (_crc32_vec(x4_arr, plaintext[index + 4]) & _MASK_8_32) | x5_low
    x6 = (_crc32_vec(x5, plaintext[index + 5]) & _MASK_8_32) | x6_low
    x7 = (_crc32_vec(x6, plaintext[index + 6]) & _MASK_8_32) | x7_low

    # compute X3
    x3 = x7
    for i in range(6, 2, -1):
        x3 = _crc32inv_vec(x3, plaintext[index + i])

    # check that X3 fits with Y1[26,32)
    y1_26_32 = np.uint32(get_yi_24_32(zlist[1], zlist[0]) & MASK_26_32)
    value = (
        ((y3_arr - np.uint32(1)) * _MULT_INV_32 - (x3 & np.uint32(0xFF)) - np.uint32(1))
        * _MULT_INV_32
        - y1_26_32
    )
    ok = value <= _MAXDIFF_26

    # filter with the first byte of the forward deciphering check
    z7 = np.uint32(zlist[7])
    if index + 8 < len(plaintext):
        xs = _crc32_vec(x7, plaintext[index + 7])
        ys = (y7_sel + (xs & np.uint32(0xFF))) * _MULT_32 + np.uint32(1)
        zs = _crc32_scalar_msb(int(z7), ys >> np.uint32(24))
        k = _KS[((zs & np.uint32(0xFFFF)) >> np.uint32(2)).astype(np.intp)]
        ok &= (np.uint32(ciphertext[offset + index + 8]) ^ k) == np.uint32(plaintext[index + 8])

    selected = np.flatnonzero(ok)

    return [
        (int(x7[j]), int(y7_sel[j]), int(x3[j]), int(y3_arr[j]))
        for j in selected
    ]
