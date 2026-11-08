"""Biham and Kocher's attack, mirroring ``Attack.cpp``."""

from __future__ import annotations

import os
from typing import List, Optional, Sequence, Tuple

from .constants import (
    CONTIGUOUS_SIZE,
    MASK_24_32,
    MASK_26_32,
    MASK_2_32,
    MASK_8_32,
    MAXDIFF_24,
    MAXDIFF_26,
    MULT_INV,
    U32,
)
from .data import Data
from .keys import Keys
from .progress import Progress, State
from .tables import (
    CRC_INV_TABLE,
    CRC_TABLE,
    MSB_PROD_FIBER2,
    MSB_PROD_FIBER3,
    get_yi_24_32,
    zi_2_16_vector,
)

__all__ = ["Attack", "attack"]

#: Total number of known plaintext bytes required by the attack.
ATTACK_SIZE = 12

#: Optional NumPy acceleration of the innermost loop.  Set ``BKCRACK_NO_NUMPY=1``
#: to force the reference pure Python code path.
_fastroots = None
if os.environ.get("BKCRACK_NO_NUMPY", "") != "1":
    try:  # pragma: no cover - trivial import guard
        from . import _fastroots as _fastroots_module

        _fastroots = _fastroots_module
    except Exception:  # pragma: no cover - NumPy missing or broken
        _fastroots = None


def _crc32(pval: int, b: int) -> int:
    return (pval >> 8) ^ CRC_TABLE[(pval & 0xFF) ^ b]


def _crc32inv(crc: int, b: int) -> int:
    return (((crc << 8) & U32) ^ CRC_INV_TABLE[crc >> 24]) ^ b


class Attack:
    """Carry out the attack for a given ``Z[2,32)`` value."""

    __slots__ = (
        "data",
        "index",
        "solutions",
        "exhaustive",
        "progress",
        "zlist",
        "ylist",
        "xlist",
        "_keystream",
        "_plaintext",
        "_ciphertext",
        "_extra_plaintext",
        "_offset",
    )

    def __init__(
        self,
        data: Data,
        index: int,
        solutions: List[Keys],
        exhaustive: bool,
        progress: Progress,
    ) -> None:
        self.data = data
        # starting index of the used plaintext and keystream
        self.index = index + 1 - CONTIGUOUS_SIZE
        self.solutions = solutions
        self.exhaustive = exhaustive
        self.progress = progress

        self.zlist = [0] * CONTIGUOUS_SIZE
        self.ylist = [0] * CONTIGUOUS_SIZE  # the first two elements are not used
        self.xlist = [0] * CONTIGUOUS_SIZE  # the first four elements are not used

        self._keystream = data.keystream
        self._plaintext = data.plaintext
        self._ciphertext = data.ciphertext
        self._extra_plaintext = data.extra_plaintext
        self._offset = data.offset

    def carryout(self, z7_2_32: int) -> None:
        """Carry out the attack for the given ``Z[2,32)`` value."""
        self.zlist[7] = z7_2_32
        self._explore_zlists(7)

    # -- Z lists -----------------------------------------------------------

    def _explore_zlists(self, i: int) -> None:
        zlist = self.zlist
        ylist = self.ylist

        if i != 0:
            # get Z{i-1}[10,32) from CRC32^-1
            zim1_10_32 = _crc32inv(zlist[i], 0) & 0xFFFFFC00

            # get Z{i-1}[2,16) values from keystream byte k{i-1}
            for zim1_2_16 in zi_2_16_vector(self._keystream[self.index + i - 1], zim1_10_32):
                zlist[i - 1] = zim1_10_32 | zim1_2_16

                # find Zi[0,2) from CRC32^-1
                zlist[i] &= MASK_2_32
                zlist[i] |= (_crc32inv(zlist[i], 0) ^ zlist[i - 1]) >> 8

                # get Y{i+1}[24,32)
                if i < 7:
                    ylist[i + 1] = get_yi_24_32(zlist[i + 1], zlist[i])

                self._explore_zlists(i - 1)
        else:
            self._explore_ylists_roots()

    def _explore_ylists_roots(self) -> None:
        """Guess ``Y7[8,24)`` and derive compatible ``Y6`` and ``X7[0,8)``."""
        if _fastroots is not None:
            self._explore_roots_fast()
            return

        ylist = self.ylist
        y7 = ylist[7]
        y6_24_32 = ylist[6] & MASK_24_32
        y6_msb = ylist[6] >> 24

        prod = (((MULT_INV * (y7 >> 24)) << 24) - MULT_INV) & U32
        fiber3 = MSB_PROD_FIBER3
        mult_inv = MULT_INV

        for y7_8_24 in range(0, 1 << 24, 1 << 8):
            # get possible Y7[0,8) values
            for y7_0_8 in fiber3[(y6_msb - (prod >> 24)) & 0xFF]:
                # filter Y7[0,8) using Y6[24,32)
                if (prod + mult_inv * y7_0_8 - y6_24_32) & U32 <= MAXDIFF_24:
                    ylist[7] = y7_0_8 | y7_8_24 | (y7 & MASK_24_32)
                    self._explore_ylists(7)

            prod = (prod + (mult_inv << 8)) & U32

    def _explore_roots_fast(self) -> None:
        """Vectorized version of the whole Y-list exploration for one Z list."""
        for x7, y7, x3, y3 in _fastroots.explore_leaf(
            self.zlist,
            self.ylist,
            self._keystream,
            self.index,
            self._plaintext,
            self._ciphertext,
            self._offset,
        ):
            self._verify(x7, x3, y7, y3)

    # -- Y lists -----------------------------------------------------------

    def _explore_ylists(self, i: int) -> None:
        ylist = self.ylist
        xlist = self.xlist

        if i != 3:
            fy = ((ylist[i] - 1) * MULT_INV) & U32
            ffy = ((fy - 1) * MULT_INV) & U32
            y_i2_24_32 = ylist[i - 2] & MASK_24_32

            # get possible LSB(Xi)
            for xi_0_8 in MSB_PROD_FIBER2[(ffy - y_i2_24_32) >> 24 & 0xFF]:
                # compute corresponding Y{i-1}
                yim1 = (fy - xi_0_8) & U32

                # filter values with Y{i-2}[24,32)
                if (
                    (ffy - MULT_INV * xi_0_8 - y_i2_24_32) & U32
                ) <= MAXDIFF_24 and (yim1 >> 24) == (ylist[i - 1] >> 24):
                    ylist[i - 1] = yim1
                    xlist[i] = xi_0_8
                    self._explore_ylists(i - 1)
        else:
            self._test_xlist()

    # -- X list ------------------------------------------------------------

    def _test_xlist(self) -> None:
        xlist = self.xlist
        ylist = self.ylist
        zlist = self.zlist

        plaintext = self._plaintext
        ciphertext = self._ciphertext
        index = self.index
        offset = self._offset

        # compute X7
        for i in range(5, 8):
            xlist[i] = (_crc32(xlist[i - 1], plaintext[index + i - 1]) & MASK_8_32) | (
                xlist[i] & 0xFF
            )

        # compute X3
        x = xlist[7]
        for i in range(6, 2, -1):
            x = _crc32inv(x, plaintext[index + i])

        # check that X3 fits with Y1[26,32)
        y1_26_32 = get_yi_24_32(zlist[1], zlist[0]) & MASK_26_32
        if (((ylist[3] - 1) * MULT_INV - (x & 0xFF) - 1) * MULT_INV - y1_26_32) & U32 > MAXDIFF_26:
            return

        self._verify(xlist[7], x, ylist[7], ylist[3])

    def _verify(self, x7: int, x3: int, y7: int, y3: int) -> None:
        """Decipher with the candidate keys and record them if they are valid."""
        plaintext = self._plaintext
        ciphertext = self._ciphertext
        index = self.index
        offset = self._offset
        zlist = self.zlist

        # decipher and filter by comparing with remaining contiguous plaintext forward
        keys_forward = Keys(x7, y7, zlist[7])
        keys_forward.update(plaintext[index + 7])

        plaintext_size = len(plaintext)
        for i in range(index + 8, plaintext_size):
            c = ciphertext[offset + i]
            if (c ^ keys_forward.keystream_byte()) != plaintext[i]:
                return
            keys_forward.update(plaintext[i])

        index_forward = offset + plaintext_size

        # and also backward
        keys_backward = Keys(x3, y3, zlist[3])
        for i in range(index + 2, -1, -1):
            c = ciphertext[offset + i]
            keys_backward.update_backward(c)
            if (c ^ keys_backward.keystream_byte()) != plaintext[i]:
                return

        index_backward = offset

        # continue filtering with extra known plaintext
        for extra_index, extra_byte in self._extra_plaintext:
            if extra_index < index_backward:
                keys_backward.update_backward_ciphertext(ciphertext, index_backward, extra_index)
                index_backward = extra_index
                p = ciphertext[index_backward] ^ keys_backward.keystream_byte()
            else:
                keys_forward.update_ciphertext(ciphertext, index_forward, extra_index)
                index_forward = extra_index
                p = ciphertext[index_forward] ^ keys_forward.keystream_byte()

            if p != extra_byte:
                return

        # all tests passed so the keys are found

        # get the keys associated with the initial state
        keys_backward.update_backward_ciphertext(ciphertext, index_backward, 0)

        self.solutions.append(keys_backward)
        self.progress.log(f"Keys: {keys_backward}")

        if not self.exhaustive:
            self.progress.state = State.EARLY_EXIT


def attack(
    data: Data,
    zi_2_32_vector: Sequence[int],
    start: int = 0,
    index: int = 7,
    jobs: int = 1,
    exhaustive: bool = False,
    progress: Optional[Progress] = None,
) -> Tuple[List[Keys], int]:
    """Iterate on ``Zi[2,32)`` candidates to try and find complete internal keys.

    Returns a ``(solutions, restart)`` tuple.  ``restart`` tells where the search
    stopped so that a later run may resume using ``--continue-attack``.
    """
    if progress is None:
        progress = Progress()

    solutions: List[Keys] = []
    worker = Attack(data, index, solutions, exhaustive, progress)

    size = len(zi_2_32_vector)
    progress.done = start
    progress.total = size

    if jobs > 1 and size - start > 1:
        from ._attack_parallel import parallel_attack

        return parallel_attack(
            data=data,
            zi_2_32_vector=zi_2_32_vector,
            start=start,
            index=index,
            jobs=jobs,
            exhaustive=exhaustive,
            progress=progress,
        )

    for i in range(start, size):
        worker.carryout(zi_2_32_vector[i])
        progress.done += 1

        if progress.state is not State.NORMAL:
            return solutions, i + 1

    return solutions, size
