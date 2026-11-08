"""Known plaintext / ciphertext preparation, mirroring ``Data.cpp``."""

from __future__ import annotations

from bisect import bisect_left
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .constants import ATTACK_SIZE, CONTIGUOUS_SIZE, ENCRYPTION_HEADER_SIZE
from .errors import DataError

__all__ = ["Data"]


class Data:
    """Normalized known plaintext and ciphertext used to carry out an attack.

    The constructor performs the same validation and normalization as the C++
    implementation:

    * offsets are shifted by the size of the encryption header so that they are
      absolute offsets in the ciphertext,
    * the optional check byte (last byte of the encryption header) is added to
      the known plaintext,
    * adjacent known plaintext fragments are merged, and the longest contiguous
      run is promoted to the main plaintext,
    * remaining fragments are sorted by distance to the attack window so that
      they filter candidates as early as possible.
    """

    __slots__ = ("ciphertext", "plaintext", "keystream", "offset", "extra_plaintext")

    def __init__(
        self,
        ciphertext: Sequence[int],
        check_byte: Optional[int] = None,
        plaintext: Sequence[int] = (),
        offset: int = 0,
        extra_plaintext: Optional[Mapping[int, int]] = None,
    ) -> None:
        ciphertext = bytes(ciphertext)
        plaintext = bytearray(plaintext)
        extra_map: Dict[int, int] = dict(extra_plaintext or {})

        # validate lengths
        if len(ciphertext) < ATTACK_SIZE:
            raise DataError(
                f"ciphertext is too small for an attack (minimum length is {ATTACK_SIZE})"
            )
        if len(ciphertext) < len(plaintext):
            raise DataError("ciphertext is smaller than plaintext")

        # validate offsets
        minimum_offset = -ENCRYPTION_HEADER_SIZE
        if offset < minimum_offset:
            raise DataError(
                f"plaintext offset {offset} is too small (minimum is {minimum_offset})"
            )
        if len(ciphertext) < ENCRYPTION_HEADER_SIZE + offset + len(plaintext):
            raise DataError(f"plaintext offset {offset} is too large")

        if extra_map:
            first_extra = min(extra_map)
            last_extra = max(extra_map)
            if first_extra < minimum_offset:
                raise DataError(
                    f"extra plaintext offset {first_extra} is too small (minimum is {minimum_offset})"
                )
            if len(ciphertext) <= ENCRYPTION_HEADER_SIZE + last_extra:
                raise DataError(f"extra plaintext offset {last_extra} is too large")

        # shift offsets to absolute values
        absolute_offset = ENCRYPTION_HEADER_SIZE + offset
        extra: list = [
            [ENCRYPTION_HEADER_SIZE + o, b] for o, b in sorted(extra_map.items())
        ]

        # include check byte at the end of the encryption header unless the byte
        # at this offset is already provided
        if check_byte is not None:
            header_end = ENCRYPTION_HEADER_SIZE - 1
            provided_by_plaintext = (
                absolute_offset <= header_end < absolute_offset + len(plaintext)
            )
            provided_by_extra = (header_end - ENCRYPTION_HEADER_SIZE) in extra_map
            if not provided_by_plaintext and not provided_by_extra:
                pos = bisect_left(extra, [header_end, 0])
                extra.insert(pos, [header_end, check_byte])

        # merge contiguous plaintext with adjacent extra plaintext
        before = bisect_left(extra, [absolute_offset, 0])
        after = bisect_left(extra, [absolute_offset + len(plaintext), 0])

        # overwrite overlapping plaintext
        for i in range(before, after):
            extra_offset, extra_byte = extra[i]
            plaintext[extra_offset - absolute_offset] = extra_byte

        # merge contiguous plaintext with extra plaintext immediately before
        while before > 0 and extra[before - 1][0] == absolute_offset - 1:
            before -= 1
            plaintext.insert(0, extra[before][1])
            absolute_offset -= 1

        # merge contiguous plaintext with extra plaintext immediately after
        while after < len(extra) and extra[after][0] == absolute_offset + len(plaintext):
            plaintext.append(extra[after][1])
            after += 1

        # discard merged extra plaintext
        del extra[before:after]

        # find the longest contiguous sequence in extra plaintext and use it as
        # contiguous plaintext if sensible
        best_start = 0
        best_end = 0
        i = 0
        while i < len(extra):
            j = i
            while j + 1 < len(extra) and extra[j + 1][0] == extra[j][0] + 1:
                j += 1
            if j - i + 1 > best_end - best_start:
                best_start, best_end = i, j + 1
            i = j + 1

        if len(plaintext) < best_end - best_start:
            previous_plaintext = plaintext
            previous_offset = absolute_offset
            range_offset = extra[best_start][0]

            # the whole run becomes the contiguous plaintext
            plaintext = bytearray(b for _, b in extra[best_start:best_end])
            del extra[best_start:best_end]

            # the former contiguous plaintext becomes extra plaintext
            for k, value in enumerate(previous_plaintext):
                extra.append([previous_offset + k, value])

            extra.sort()
            absolute_offset = range_offset

        # check that there is enough known plaintext
        if len(plaintext) < CONTIGUOUS_SIZE:
            raise DataError(
                f"not enough contiguous plaintext ({len(plaintext)} bytes available, "
                f"minimum is {CONTIGUOUS_SIZE})"
            )
        if len(plaintext) + len(extra) < ATTACK_SIZE:
            raise DataError(
                f"not enough plaintext ({len(plaintext) + len(extra)} bytes available, "
                f"minimum is {ATTACK_SIZE})"
            )

        # reorder remaining extra plaintext for filtering: closest to the attack
        # window first
        pivot = absolute_offset + CONTIGUOUS_SIZE

        def distance_key(fragment):
            off = fragment[0]
            return (abs(off - pivot), 0 if off < absolute_offset else 1)

        extra.sort(key=distance_key)

        self.ciphertext = ciphertext
        self.plaintext = bytes(plaintext)
        self.offset = absolute_offset
        self.extra_plaintext: Tuple[Tuple[int, int], ...] = tuple(
            (o, b) for o, b in extra
        )
        self.keystream = bytes(
            p ^ ciphertext[absolute_offset + i] for i, p in enumerate(self.plaintext)
        )

    def __repr__(self) -> str:
        return (
            f"Data(offset={self.offset}, plaintext={len(self.plaintext)} bytes, "
            f"extra={len(self.extra_plaintext)}, ciphertext={len(self.ciphertext)} bytes)"
        )
