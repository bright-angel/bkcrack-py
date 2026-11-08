"""Command line argument parsing, mirroring ``Arguments.cpp``.

The class :class:`Arguments` behaves like its C++ counterpart: it consumes the
command line token by token, validates the combination of options and can load
the data needed to carry out an attack.

Options taking free-form data (passwords, charsets, masks, hexadecimal blobs)
are handled as bytes, exactly like the C++ implementation which receives raw
``char*`` values from the operating system.  Filenames stay :class:`str`.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from .constants import ENCRYPTION_HEADER_SIZE
from .data import Data
from .errors import ArgumentsError
from .file import load_stream, open_input
from .keys import Keys
from .ziparchive import Encryption, Zip

__all__ = ["Arguments", "LengthInterval"]


#: Value of ``std::numeric_limits<std::size_t>::max()`` on 64-bit platforms.
SIZE_MAX = (1 << 64) - 1

_INT_MIN = -(2**31)
_INT_MAX = 2**31 - 1
_U64_MAX = (1 << 64) - 1

_WHITESPACE = " \t\n\v\f\r"
_HEX_DIGITS = "0123456789abcdefABCDEF"


class LengthInterval:
    """Range of password lengths to try during password recovery.

    Both bounds are inclusive.  Intersecting two intervals is done with the
    ``&`` operator, like in the original implementation.
    """

    __slots__ = ("min_length", "max_length")

    def __init__(self, min_length: int = 0, max_length: int = SIZE_MAX) -> None:
        self.min_length = min_length
        self.max_length = max_length

    def __and__(self, other: "LengthInterval") -> "LengthInterval":
        return LengthInterval(
            max(self.min_length, other.min_length),
            min(self.max_length, other.max_length),
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"LengthInterval({self.min_length}, {self.max_length})"


# -- integer parsing ------------------------------------------------------


def _parse_c_integer(value: str, unsigned: bool) -> int:
    """Mimic ``std::stoi``/``std::stoull`` with base 0.

    Like the C++ standard library functions, parsing stops at the first
    character that is not a digit of the detected base.
    """
    text = value
    position = 0
    length = len(text)

    while position < length and text[position] in _WHITESPACE:
        position += 1

    negative = False
    if position < length and text[position] in "+-":
        negative = text[position] == "-"
        position += 1

    base = 10
    if position < length and text[position] == "0":
        if position + 1 < length and text[position + 1] in "xX":
            base = 16
            position += 2
        else:
            base = 8

    digits = "0123456789abcdef"[:base] + ("ABCDEF" if base == 16 else "")
    start = position
    number = 0
    while position < length and text[position] in digits:
        number = number * base + int(text[position], 16)
        position += 1

    if position == start:
        raise ArgumentsError(f'expected an integer, got "{value}"')

    if negative:
        number = -number

    if unsigned:
        number &= _U64_MAX
        if number > _U64_MAX:  # pragma: no cover - unreachable after masking
            raise ArgumentsError(f"integer value {value} is out of range")
    elif not _INT_MIN <= number <= _INT_MAX:
        raise ArgumentsError(f"integer value {value} is out of range")

    return number


def _parse_int(value: str) -> int:
    return _parse_c_integer(value, unsigned=False)


def _parse_size(value: str) -> int:
    return _parse_c_integer(value, unsigned=True)


def _parse_interval(value: str) -> Union[LengthInterval, int]:
    """Parse ``<min>..<max>``, ``<min>..``, ``..<max>`` or a plain number."""
    separator = ".."
    index = value.find(separator)
    if index < 0:
        return _parse_size(value)

    interval = LengthInterval()
    if index > 0:
        interval.min_length = _parse_size(value[:index])

    begin = index + len(separator)
    if begin < len(value):
        interval.max_length = _parse_size(value[begin:])

    return interval


# -- charsets -------------------------------------------------------------


def _char_range(first: int, last: int) -> Set[int]:
    return set(range(first, last + 1))


_LOWERCASE = _char_range(ord("a"), ord("z"))
_UPPERCASE = _char_range(ord("A"), ord("Z"))
_DIGITS = _char_range(ord("0"), ord("9"))
_ALPHANUM = _LOWERCASE | _UPPERCASE | _DIGITS
_PRINTABLE = _char_range(0x20, 0x7E)
_PUNCTUATION = _PRINTABLE - _ALPHANUM
_ALL_BYTES = _char_range(0x00, 0xFF)

_BUILTIN_CHARSETS: Dict[int, Set[int]] = {
    ord("l"): _LOWERCASE,
    ord("u"): _UPPERCASE,
    ord("d"): _DIGITS,
    ord("a"): _ALPHANUM,
    ord("p"): _PRINTABLE,
    ord("s"): _PUNCTUATION,
    ord("b"): _ALL_BYTES,
    ord("?"): {ord("?")},
}


def _byte_to_text(value: int) -> str:
    """Render a single byte the way C++ would print its ``char``."""
    return bytes([value]).decode("latin-1")


class Arguments:
    """Parse and store command line arguments."""

    def __init__(self, args: Sequence[str]) -> None:
        # options with a value
        self.cipher_file: Optional[str] = None
        self.cipher_index: Optional[int] = None
        self.cipher_archive: Optional[str] = None

        self.plain_file: Optional[str] = None
        self.plain_index: Optional[int] = None
        self.plain_archive: Optional[str] = None

        self.plain_file_prefix: int = 1 << 20
        self.offset: int = 0
        self.extra_plaintext: Dict[int, int] = {}
        self.ignore_check_byte: bool = False

        self.attack_start: int = 0
        self.password: Optional[bytes] = None
        self.keys: Optional[Keys] = None

        self.deciphered_file: Optional[str] = None
        self.keep_header: bool = False
        self.decrypted_archive: Optional[str] = None

        self.change_password: Optional[Tuple[str, bytes]] = None
        self.change_keys: Optional[Tuple[str, Keys]] = None

        self.bruteforce: Optional[List[int]] = None
        self.length: Optional[LengthInterval] = None
        self.mask: Optional[List[List[int]]] = None
        self.recovery_start: bytes = b""

        self.jobs: int = os.cpu_count() or 2
        self.exhaustive: bool = False

        self.info_archive: Optional[str] = None
        self.version: bool = False
        self.help: bool = False

        # parser state
        self._args = list(args)
        self._position = 0
        self._charsets: Dict[int, Set[int]] = dict(_BUILTIN_CHARSETS)
        self._raw_charsets: Dict[int, bytes] = {}
        self._raw_bruteforce: Optional[bytes] = None
        self._raw_mask: Optional[bytes] = None

        while not self._finished():
            self._parse_argument()

        if self.help or self.version or self.info_archive is not None:
            return  # no further checks are needed for those options

        self._compute_deferred()
        self._check_constraints()

    # -- construction helpers ---------------------------------------------

    @classmethod
    def parse(cls, args: Sequence[str]) -> "Arguments":
        """Parse *args* (without the program name)."""
        return cls(args)

    @classmethod
    def from_command_line(cls) -> "Arguments":
        """Parse ``sys.argv``."""
        return cls(sys.argv[1:])

    def _compute_deferred(self) -> None:
        if self._raw_bruteforce is not None:
            self.bruteforce = sorted(self._resolve_charset(self._raw_bruteforce))

        if self._raw_mask is not None:
            self.mask = []
            raw = self._raw_mask
            position = 0
            length = len(raw)
            while position < length:
                byte = raw[position]
                if byte == ord("?"):
                    position += 1
                    if position == length:
                        self.mask.append([ord("?")])
                        break
                    self.mask.append(
                        sorted(self._resolve_charset(b"?" + raw[position : position + 1]))
                    )
                else:
                    self.mask.append([byte])
                position += 1

    def _check_constraints(self) -> None:
        if self.keys is not None:
            if not (
                self.deciphered_file
                or self.decrypted_archive
                or self.change_password
                or self.change_keys
                or self.bruteforce
                or self.mask
            ):
                raise ArgumentsError(
                    "-d, -D, -U, --change-keys, --bruteforce or --mask parameter is "
                    "missing (required by -k)"
                )
        elif self.password is None:
            if self.cipher_file and self.cipher_index is not None:
                raise ArgumentsError("-c and --cipher-index cannot be used at the same time")
            if self.plain_file and self.plain_index is not None:
                raise ArgumentsError("-p and --plain-index cannot be used at the same time")

            if not self.cipher_file and self.cipher_index is None:
                raise ArgumentsError("-c or --cipher-index parameter is missing")
            if not self.plain_file and self.plain_index is None and not self.extra_plaintext:
                raise ArgumentsError("-p, --plain-index or -x parameter is missing")

            if self.plain_archive and not self.plain_file and self.plain_index is None:
                raise ArgumentsError("-p or --plain-index parameter is missing (required by -P)")

            if self.cipher_index is not None and not self.cipher_archive:
                raise ArgumentsError("-C parameter is missing (required by --cipher-index)")
            if self.plain_index is not None and not self.plain_archive:
                raise ArgumentsError("-P parameter is missing (required by --plain-index)")

            minimum_offset = -ENCRYPTION_HEADER_SIZE
            if self.offset < minimum_offset:
                raise ArgumentsError(
                    f"plaintext offset {self.offset} is too small "
                    f"(minimum is {minimum_offset})"
                )
            if self.extra_plaintext and min(self.extra_plaintext) < minimum_offset:
                raise ArgumentsError(
                    f"extra plaintext offset {min(self.extra_plaintext)} is too small "
                    f"(minimum is {minimum_offset})"
                )

        if self.deciphered_file and not self.cipher_file and self.cipher_index is None:
            raise ArgumentsError("-c or --cipher-index parameter is missing (required by -d)")
        if (
            self.deciphered_file
            and not self.cipher_archive
            and self.deciphered_file == self.cipher_file
        ):
            raise ArgumentsError("-c and -d parameters must point to different files")

        if self.decrypted_archive and not self.cipher_archive:
            raise ArgumentsError("-C parameter is missing (required by -D)")
        if self.decrypted_archive and self.decrypted_archive == self.cipher_archive:
            raise ArgumentsError("-C and -D parameters must point to different files")

        if self.change_password and not self.cipher_archive:
            raise ArgumentsError("-C parameter is missing (required by -U)")
        if self.change_password and self.change_password[0] == self.cipher_archive:
            raise ArgumentsError("-C and -U parameters must point to different files")

        if self.change_keys and not self.cipher_archive:
            raise ArgumentsError("-C parameter is missing (required by --change-keys)")
        if self.change_keys and self.change_keys[0] == self.cipher_archive:
            raise ArgumentsError("-C and --change-keys parameters must point to different files")

        if self.length is not None and self.bruteforce is None:
            raise ArgumentsError("--bruteforce parameter is missing (required by --length)")

        if self.bruteforce and self.mask:
            raise ArgumentsError("--bruteforce and --mask cannot be used at the same time")

    # -- data loading ------------------------------------------------------

    def load_data(self) -> Data:
        """Load the known plaintext and ciphertext described by the arguments."""
        plaintext = b""
        if self.plain_archive is not None:
            with open_input(self.plain_archive) as stream:
                archive = Zip(stream.read())
            entry = (
                archive[self.plain_file]
                if self.plain_file is not None
                else archive[self.plain_index]
            )
            Zip.check_encryption(entry, Encryption.NONE)
            plaintext = archive.load(entry, self.plain_file_prefix)
        elif self.plain_file is not None:
            with open_input(self.plain_file) as stream:
                plaintext = load_stream(stream, self.plain_file_prefix)

        # load ciphertext needed by the attack
        needed = ENCRYPTION_HEADER_SIZE
        if plaintext:
            needed = max(needed, ENCRYPTION_HEADER_SIZE + self.offset + len(plaintext))
        if self.extra_plaintext:
            needed = max(needed, ENCRYPTION_HEADER_SIZE + max(self.extra_plaintext) + 1)

        ciphertext = b""
        check_byte: Optional[int] = None
        if self.cipher_archive is not None:
            with open_input(self.cipher_archive) as stream:
                archive = Zip(stream.read())
            entry = (
                archive[self.cipher_file]
                if self.cipher_file is not None
                else archive[self.cipher_index]
            )
            Zip.check_encryption(entry, Encryption.TRADITIONAL)
            ciphertext = archive.load(entry, needed)

            if not self.ignore_check_byte:
                check_byte = entry.check_byte
        else:
            with open_input(self.cipher_file) as stream:
                ciphertext = load_stream(stream, needed)

        return Data(ciphertext, check_byte, plaintext, self.offset, self.extra_plaintext)

    # -- charset resolution ------------------------------------------------

    def _resolve_charset(self, raw_charset: bytes) -> Set[int]:
        charset: Set[int] = set()
        position = 0
        length = len(raw_charset)

        while position < length:
            byte = raw_charset[position]
            if byte == ord("?"):  # escape character to reference other charsets
                position += 1
                if position == length:
                    charset.add(ord("?"))
                    break

                identifier = raw_charset[position]
                raw = self._raw_charsets.get(identifier)
                if raw is not None:
                    # insert into _charsets first to mark the identifier as being
                    # resolved and detect cycles
                    if identifier in self._charsets:
                        raise ArgumentsError(
                            f"circular reference resolving charset ?{_byte_to_text(identifier)}"
                        )
                    self._charsets[identifier] = set()
                    self._charsets[identifier] = self._resolve_charset(raw)
                    del self._raw_charsets[identifier]

                resolved = self._charsets.get(identifier)
                if resolved is None:
                    raise ArgumentsError(f"unknown charset ?{_byte_to_text(identifier)}")
                charset |= resolved
            else:
                charset.add(byte)

            position += 1

        return charset

    # -- low level readers -------------------------------------------------

    def _finished(self) -> bool:
        return self._position == len(self._args)

    def _read_string(self, description: str) -> str:
        if self._finished():
            raise ArgumentsError(f"expected {description}, got nothing")

        value = self._args[self._position]
        self._position += 1
        return value

    def _read_bytes(self, description: str) -> bytes:
        return os.fsencode(self._read_string(description))

    def _read_option(self, description: str) -> str:
        value = self._read_string(description)
        option = _OPTIONS.get(value)
        if option is None:
            raise ArgumentsError(f"unknown option {value}")
        return option

    def _read_int(self, description: str) -> int:
        return _parse_int(self._read_string(description))

    def _read_size(self, description: str) -> int:
        return _parse_size(self._read_string(description))

    def _read_hex(self, description: str) -> bytes:
        value = self._read_string(description)

        if len(value) % 2:
            raise ArgumentsError(f"expected an even-length string, got {value}")
        for character in value:
            if character not in _HEX_DIGITS:
                raise ArgumentsError(f"expected {description} in hexadecimal, got {value}")

        return bytes(int(value[i : i + 2], 16) for i in range(0, len(value), 2))

    def _read_key(self, description: str) -> int:
        value = self._read_string(description)

        if len(value) > 8:
            raise ArgumentsError(f"expected a string of length 8 or less, got {value}")
        for character in value:
            if character not in _HEX_DIGITS:
                raise ArgumentsError(f"expected {description} in hexadecimal, got {value}")

        return int(value, 16) if value else 0

    def _read_raw_charset(self, description: str) -> bytes:
        charset = self._read_bytes(description)

        if not charset:
            raise ArgumentsError(f"{description} is empty")

        return charset

    # -- option parsing ----------------------------------------------------

    def _parse_argument(self) -> None:
        option = self._read_option("an option")

        if option == "cipher_file":
            self.cipher_file = self._read_string("ciphertext")
        elif option == "cipher_index":
            self.cipher_index = self._read_size("index")
        elif option == "cipher_archive":
            self.cipher_archive = self._read_string("encryptedzip")
        elif option == "plain_file":
            self.plain_file = self._read_string("plaintext")
        elif option == "plain_index":
            self.plain_index = self._read_size("index")
        elif option == "plain_archive":
            self.plain_archive = self._read_string("plainzip")
        elif option == "plain_file_prefix":
            self.plain_file_prefix = self._read_size("size")
        elif option == "offset":
            self.offset = self._read_int("offset")
        elif option == "extra_plaintext":
            index = self._read_int("offset")
            for byte in self._read_hex("data"):
                self.extra_plaintext[index] = byte
                index += 1
        elif option == "ignore_check_byte":
            self.ignore_check_byte = True
        elif option == "attack_start":
            self.attack_start = self._read_int("checkpoint")
        elif option == "password":
            self.password = self._read_bytes("password")
        elif option == "keys":
            self.keys = Keys(
                self._read_key("X"), self._read_key("Y"), self._read_key("Z")
            )
        elif option == "deciphered_file":
            self.deciphered_file = self._read_string("decipheredfile")
        elif option == "keep_header":
            self.keep_header = True
        elif option == "decrypted_archive":
            self.decrypted_archive = self._read_string("decipheredzip")
        elif option == "change_password":
            unlocked = self._read_string("unlockedzip")
            new_password = self._read_bytes("password")
            self.change_password = (unlocked, new_password)
        elif option == "change_keys":
            unlocked = self._read_string("unlockedzip")
            new_keys = Keys(
                self._read_key("X"), self._read_key("Y"), self._read_key("Z")
            )
            self.change_keys = (unlocked, new_keys)
        elif option == "bruteforce":
            self._raw_bruteforce = self._read_raw_charset(
                "charset for bruteforce password recovery"
            )
        elif option == "length":
            interval = _parse_interval(self._read_string("length"))
            if isinstance(interval, int):
                interval = LengthInterval(interval, interval)
            self.length = (self.length or LengthInterval()) & interval
        elif option == "recover_password":
            interval = _parse_interval(self._read_string("length"))
            if isinstance(interval, int):
                interval = LengthInterval(0, interval)
            self.length = (self.length or LengthInterval()) & interval
            self._raw_bruteforce = self._read_raw_charset(
                "charset for bruteforce password recovery"
            )
        elif option == "mask":
            self._raw_mask = self._read_bytes("mask")
        elif option == "charset":
            identifier = self._read_bytes("identifier")
            if len(identifier) != 1:
                raise ArgumentsError(
                    "charset identifier must be a single character, got "
                    f'"{identifier.decode("utf-8", "replace")}"'
                )
            key = identifier[0]
            if key in self._charsets or key in self._raw_charsets:
                raise ArgumentsError(
                    f"charset ?{_byte_to_text(key)} is already defined, "
                    "it cannot be redefined"
                )
            self._raw_charsets[key] = self._read_raw_charset(
                f"charset ?{_byte_to_text(key)}"
            )
        elif option == "recovery_start":
            self.recovery_start = self._read_hex("checkpoint")
        elif option == "jobs":
            self.jobs = self._read_int("count")
        elif option == "exhaustive":
            self.exhaustive = True
        elif option == "info_archive":
            self.info_archive = self._read_string("zipfile")
        elif option == "version":
            self.version = True
        elif option == "help":
            self.help = True
        else:  # pragma: no cover - the option table and the dispatch are in sync
            raise AssertionError(f"unhandled option {option}")

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"Arguments({vars(self)!r})"


_OPTIONS: Dict[str, str] = {
    "-c": "cipher_file",
    "--cipher-file": "cipher_file",
    "--cipher-index": "cipher_index",
    "-C": "cipher_archive",
    "--cipher-zip": "cipher_archive",
    "-p": "plain_file",
    "--plain-file": "plain_file",
    "--plain-index": "plain_index",
    "-P": "plain_archive",
    "--plain-zip": "plain_archive",
    "-t": "plain_file_prefix",
    "--truncate": "plain_file_prefix",
    "-o": "offset",
    "--offset": "offset",
    "-x": "extra_plaintext",
    "--extra": "extra_plaintext",
    "--ignore-check-byte": "ignore_check_byte",
    "--continue-attack": "attack_start",
    "--password": "password",
    "-k": "keys",
    "--keys": "keys",
    "-d": "deciphered_file",
    "--decipher": "deciphered_file",
    "--keep-header": "keep_header",
    "-D": "decrypted_archive",
    "--decrypt": "decrypted_archive",
    "-U": "change_password",
    "--change-password": "change_password",
    "--change-keys": "change_keys",
    "-b": "bruteforce",
    "--bruteforce": "bruteforce",
    "-l": "length",
    "--length": "length",
    "-r": "recover_password",
    "--recover-password": "recover_password",
    "-m": "mask",
    "--mask": "mask",
    "-s": "charset",
    "--charset": "charset",
    "--continue-recovery": "recovery_start",
    "-j": "jobs",
    "--jobs": "jobs",
    "-e": "exhaustive",
    "--exhaustive": "exhaustive",
    "-L": "info_archive",
    "--list": "info_archive",
    "--version": "version",
    "-h": "help",
    "--help": "help",
}
