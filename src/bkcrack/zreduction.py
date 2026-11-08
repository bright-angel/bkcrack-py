"""Generation and reduction of Z values, mirroring ``Zreduction.cpp``."""

from __future__ import annotations

from typing import List, Sequence

from .constants import CONTIGUOUS_SIZE, MASK_10_32
from .progress import Progress, State
from .tables import CRC_INV_TABLE, KEYSTREAM_EXISTS, KEYSTREAM_INV

__all__ = ["Zreduction"]

#: Number of ``Zi[2,16)`` values compatible with each keystream byte, indexed by
#: ``(Zi & 0xffff) >> 10``.  Precomputed to avoid repeated ``len()`` calls.
_INV_COUNT = [[len(item) for item in row] for row in KEYSTREAM_INV]

_U32 = 0xFFFFFFFF


def _crc32inv(crc: int, b: int) -> int:
    return (((crc << 8) & _U32) ^ CRC_INV_TABLE[crc >> 24]) ^ b


class Zreduction:
    """Generate ``Zi[10,32)`` values from the last keystream byte.

    Then reduce the set using the rest of the keystream, and finally expand the
    remaining values to full ``Zi[2,32)`` candidates.
    """

    __slots__ = ("keystream", "zi_vector", "index")

    def __init__(self, keystream: Sequence[int]) -> None:
        self.keystream = bytes(keystream)
        self.index = len(self.keystream) - 1

        # Generate Zi[10,32) values compatible with the last keystream byte.
        # The compatibility test only depends on the 6 low bits of the shifted
        # value, so all 64-value blocks share the same pattern.
        exists = KEYSTREAM_EXISTS[self.keystream[self.index]]
        offsets = [r for r in range(64) if (exists >> r) & 1]

        candidates: List[int] = []
        append = candidates.append
        for base in range(0, 1 << 22, 64):
            for r in offsets:
                append((base + r) << 10)

        self.zi_vector = candidates

    def reduce(self, progress: Progress) -> None:
        """Reduce ``Zi[10,32)`` candidates using extra contiguous keystream."""
        track_size_threshold = 1 << 16
        wait_size_threshold = 1 << 8

        tracking = False
        best_copy: List[int] = []
        best_index = self.index
        best_size = track_size_threshold

        waiting = False
        wait = 0

        keystream = self.keystream
        inv = KEYSTREAM_INV
        inv_count = _INV_COUNT
        exists = KEYSTREAM_EXISTS
        crc32inv = _crc32inv
        mask_10_32 = MASK_10_32

        zi = self.zi_vector

        progress.done = 0
        progress.total = len(keystream) - CONTIGUOUS_SIZE

        i = self.index
        while i >= CONTIGUOUS_SIZE:
            k_i = keystream[i]
            k_prev = keystream[i - 1]
            exists_prev = exists[k_prev]
            vec_table = inv[k_i]
            count_table = inv_count[k_prev]

            zim1_vector: List[int] = []
            append = zim1_vector.append
            seen = bytearray(1 << 19)  # bitset of Zi[10,32) >> 10 values, 2**22 bits
            number_of_zim1_2_32 = 0

            for zi_10_32 in zi:
                for zi_2_16 in vec_table[(zi_10_32 & 0xFFFF) >> 10]:
                    # get Z{i-1}[10,32) from CRC32^-1
                    zim1_10_32 = crc32inv(zi_10_32 | zi_2_16, 0) & mask_10_32
                    index10 = zim1_10_32 >> 10

                    byte_index = index10 >> 3
                    bit = 1 << (index10 & 7)
                    if seen[byte_index] & bit:
                        continue
                    # keep only those compatible with keystream{i-1}
                    if not (exists_prev >> ((zim1_10_32 & 0xFFFF) >> 10)) & 1:
                        continue

                    seen[byte_index] |= bit
                    append(zim1_10_32)
                    number_of_zim1_2_32 += count_table[(zim1_10_32 & 0xFFFF) >> 10]

            # update smallest vector tracking
            if number_of_zim1_2_32 <= best_size:
                tracking = True
                best_index = i - 1
                best_size = number_of_zim1_2_32
                waiting = False
            elif tracking:
                if best_index == i:
                    # hit a minimum: keep a copy because the vector is about to grow
                    best_copy = zi

                    if best_size <= wait_size_threshold:
                        waiting = True
                        wait = best_size * 4  # arbitrary multiplicative constant

                if waiting:
                    wait -= 1
                    if wait == 0:
                        progress.state = State.EARLY_EXIT
                        break

            zi = zim1_vector
            progress.done += 1
            i -= 1

        if tracking:
            # use the best copy unless it already is the current vector
            if best_index != CONTIGUOUS_SIZE - 1:
                zi = best_copy
            self.index = best_index
        else:
            self.index = CONTIGUOUS_SIZE - 1

        self.zi_vector = zi

    def generate(self) -> None:
        """Expand ``Zi[10,32)`` values into ``Zi[2,32)`` values."""
        zi = self.zi_vector
        vec_table = KEYSTREAM_INV[self.keystream[self.index]]

        number_of_zi_10_32 = len(zi)
        for i in range(number_of_zi_10_32):
            zi_2_16_vector = vec_table[(zi[i] & 0xFFFF) >> 10]
            for zi_2_16 in zi_2_16_vector[1:]:
                zi.append(zi[i] | zi_2_16)
            zi[i] |= zi_2_16_vector[0]

    @property
    def candidates(self) -> List[int]:
        """Return the generated ``Zi[2,32)`` values."""
        return self.zi_vector
