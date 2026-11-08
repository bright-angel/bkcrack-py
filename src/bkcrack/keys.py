"""The three-word cipher state, mirroring ``include/bkcrack/Keys.hpp``."""

from __future__ import annotations

from typing import Iterable, Union

from .constants import DEFAULT_X, DEFAULT_Y, DEFAULT_Z, MULT, MULT_INV, U32
from .tables import crc32, crc32inv, keystream_byte

__all__ = ["Keys"]

BytesLike = Union[bytes, bytearray, memoryview, Iterable[int]]


class Keys:
    """State of the traditional PKWARE keystream generator.

    The state is made of three 32-bit integers ``x``, ``y`` and ``z``.  It is
    updated with each plaintext byte and produces one keystream byte per update.
    """

    __slots__ = ("x", "y", "z")

    def __init__(self, x: int = DEFAULT_X, y: int = DEFAULT_Y, z: int = DEFAULT_Z) -> None:
        self.x = x & U32
        self.y = y & U32
        self.z = z & U32

    @classmethod
    def from_password(cls, password: Union[str, bytes, bytearray]) -> "Keys":
        """Construct the state associated with *password*.

        Text passwords are encoded with UTF-8, which matches how the bytes are
        passed on the command line on most systems.
        """
        if isinstance(password, str):
            password = password.encode("utf-8")

        keys = cls()
        for p in password:
            keys.update(p)
        return keys

    def copy(self) -> "Keys":
        """Return an independent copy of this state."""
        return Keys(self.x, self.y, self.z)

    # -- forward updates ---------------------------------------------------

    def update(self, p: int) -> None:
        """Update the state with a plaintext byte."""
        x = crc32(self.x, p)
        self.x = x
        y = ((self.y + (x & 0xFF)) * MULT + 1) & U32
        self.y = y
        self.z = crc32(self.z, y >> 24)

    def update_ciphertext(self, ciphertext: BytesLike, current: int, target: int) -> None:
        """Update the state forward from index *current* to *target* using ciphertext."""
        for i in range(current, target):
            self.update(ciphertext[i] ^ self.keystream_byte())

    # -- backward updates --------------------------------------------------

    def update_backward(self, c: int) -> None:
        """Update the state backward with a ciphertext byte."""
        z = crc32inv(self.z, self.y >> 24)
        self.z = z
        self.y = ((self.y - 1) * MULT_INV - (self.x & 0xFF)) & U32
        self.x = crc32inv(self.x, c ^ keystream_byte(z))

    def update_backward_plaintext(self, p: int) -> None:
        """Update the state backward with a plaintext byte."""
        z = crc32inv(self.z, self.y >> 24)
        self.z = z
        self.y = ((self.y - 1) * MULT_INV - (self.x & 0xFF)) & U32
        self.x = crc32inv(self.x, p)

    def update_backward_ciphertext(self, ciphertext: BytesLike, current: int, target: int) -> None:
        """Update the state backward from index *current* down to *target*."""
        for i in range(current - 1, target - 1, -1):
            self.update_backward(ciphertext[i])

    # -- accessors ---------------------------------------------------------

    def keystream_byte(self) -> int:
        """Return the keystream byte derived from the current state."""
        return keystream_byte(self.z)

    @property
    def k(self) -> int:
        """Keystream byte derived from the current state (alias of :meth:`keystream_byte`)."""
        return keystream_byte(self.z)

    def as_tuple(self) -> tuple:
        return (self.x, self.y, self.z)

    # -- dunder ------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Keys):
            return NotImplemented
        return self.x == other.x and self.y == other.y and self.z == other.z

    def __hash__(self) -> int:
        return hash((self.x, self.y, self.z))

    def __str__(self) -> str:
        return f"{self.x:08x} {self.y:08x} {self.z:08x}"

    def __repr__(self) -> str:
        return f"Keys(0x{self.x:08x}, 0x{self.y:08x}, 0x{self.z:08x})"
