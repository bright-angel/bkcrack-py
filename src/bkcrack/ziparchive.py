"""Zip archive parsing and rewriting, mirroring ``Zip.cpp``.

The original implementation is stream based; this port works on an in-memory
``bytes`` object and produces the exact same output bytes for the supported
operations (decrypting an archive, changing its keys, deciphering entry data).

Zip64 extensions are supported.  Spanned archives, strong encryption and
language encoding flags are rejected like in the reference implementation.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Iterable, List, Optional, Sequence, Tuple

from .constants import ENCRYPTION_HEADER_SIZE
from .errors import ZipError
from .keys import Keys

__all__ = ["Zip", "Entry", "Encryption", "Compression", "decipher"]


class Encryption(Enum):
    """Encryption algorithm of a zip entry."""

    NONE = "none"
    TRADITIONAL = "traditional"
    UNSUPPORTED = "unsupported"


class Compression(IntEnum):
    """Compression algorithm of a zip entry (not exhaustive)."""

    STORE = 0
    SHRINK = 1
    IMPLODE = 6
    DEFLATE = 8
    DEFLATE64 = 9
    BZIP2 = 12
    LZMA = 14
    ZSTANDARD = 93
    MP3 = 94
    XZ = 95
    JPEG = 96
    WAVPACK = 97
    PPMD = 98


@dataclass
class Entry:
    """Information about a zip entry."""

    name: bytes
    encryption: Encryption
    compression: int
    crc32: int
    offset: int
    packed_size: int
    uncompressed_size: int
    check_byte: int

    @property
    def name_text(self) -> str:
        return self.name.decode("utf-8", "replace")


_SIG_LOCAL = 0x04034B50
_SIG_DATA_DESCRIPTOR = 0x08074B50
_SIG_CENTRAL = 0x02014B50
_SIG_ZIP64_EOCD = 0x06064B50
_SIG_ZIP64_LOCATOR = 0x07064B50
_SIG_EOCD = 0x06054B50

_AES_EXTRA_ID = 0x9901
_UNICODE_PATH_EXTRA_ID = 0x7075
_ZIP64_EXTRA_ID = 0x0001


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise ZipError("could not read zip structure")
    return data[offset] | (data[offset + 1] << 8)


def _u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise ZipError("could not read zip structure")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    if offset + 8 > len(data):
        raise ZipError("could not read zip structure")
    return struct.unpack_from("<Q", data, offset)[0]


def _p16(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def _p32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _p64(value: int) -> bytes:
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


class _Zip64Extra:
    """Parsed ZIP64 extra field."""

    def __init__(
        self,
        uncompressed_size: Optional[int] = None,
        compressed_size: Optional[int] = None,
        header_offset: Optional[int] = None,
        disk_start_number: Optional[int] = None,
    ) -> None:
        self.uncompressed_size = uncompressed_size
        self.compressed_size = compressed_size
        self.header_offset = header_offset
        self.disk_start_number = disk_start_number

    def payload(self) -> bytes:
        out = bytearray()
        if self.uncompressed_size is not None:
            out += _p64(self.uncompressed_size)
        if self.compressed_size is not None:
            out += _p64(self.compressed_size)
        if self.header_offset is not None:
            out += _p64(self.header_offset)
        if self.disk_start_number is not None:
            out += _p32(self.disk_start_number)
        return bytes(out)


class _ExtraField:
    """Ordered list of extra field blocks."""

    def __init__(self, blocks: Optional[List[Tuple[int, object]]] = None) -> None:
        # each block is (header_id, payload) where payload is bytes or _Zip64Extra
        self.blocks: List[Tuple[int, object]] = blocks if blocks is not None else []

    @classmethod
    def parse(
        cls,
        data: bytes,
        offset: int,
        length: int,
        uncompressed_size_32: int,
        compressed_size_32: int,
        header_offset_32: Optional[int] = None,
        disk_start_number_16: Optional[int] = None,
    ) -> Tuple["_ExtraField", int]:
        extra = cls()
        remaining = length
        position = offset

        while remaining:
            if remaining < 4:
                raise ZipError("could not read extra field")

            header_id = _u16(data, position)
            data_size = _u16(data, position + 2)
            position += 4
            remaining -= 4

            if remaining < data_size:
                raise ZipError("could not read extra field")

            payload = data[position : position + data_size]
            if len(payload) != data_size:
                raise ZipError("could not read extra field")

            if header_id == _AES_EXTRA_ID:
                if data_size != 7:
                    raise ZipError("could not read AES extra field")
                extra.blocks.append((header_id, payload))
            elif header_id == _UNICODE_PATH_EXTRA_ID:
                if data_size < 5:
                    raise ZipError("could not read Info-Zip Unicode Path extra field")
                extra.blocks.append((header_id, payload))
            elif header_id == _ZIP64_EXTRA_ID:
                extra.blocks.append(
                    (
                        header_id,
                        _parse_zip64(
                            payload,
                            uncompressed_size_32,
                            compressed_size_32,
                            header_offset_32,
                            disk_start_number_16,
                        ),
                    )
                )
            else:
                extra.blocks.append((header_id, payload))

            position += data_size
            remaining -= data_size

        return extra, position

    def write(self) -> bytes:
        out = bytearray()
        for header_id, payload in self.blocks:
            if isinstance(payload, _Zip64Extra):
                raw = payload.payload()
            else:
                raw = payload
            out += _p16(header_id)
            out += _p16(len(raw))
            out += raw
        return bytes(out)

    def find_aes(self) -> Optional[bytes]:
        for header_id, payload in self.blocks:
            if header_id == _AES_EXTRA_ID:
                return payload  # type: ignore[return-value]
        return None

    def find_unicode_path(self) -> Optional[bytes]:
        for header_id, payload in self.blocks:
            if header_id == _UNICODE_PATH_EXTRA_ID:
                return payload  # type: ignore[return-value]
        return None

    def find_zip64(self) -> Optional[_Zip64Extra]:
        for header_id, payload in self.blocks:
            if header_id == _ZIP64_EXTRA_ID and isinstance(payload, _Zip64Extra):
                return payload
        return None


def _parse_zip64(
    payload: bytes,
    uncompressed_size_32: int,
    compressed_size_32: int,
    header_offset_32: Optional[int],
    disk_start_number_16: Optional[int],
) -> _Zip64Extra:
    result = _Zip64Extra()
    remaining = len(payload)
    position = 0

    if 8 <= remaining and uncompressed_size_32 == 0xFFFFFFFF:
        result.uncompressed_size = _u64(payload, position)
        position += 8
        remaining -= 8
    if 8 <= remaining and compressed_size_32 == 0xFFFFFFFF:
        result.compressed_size = _u64(payload, position)
        position += 8
        remaining -= 8
    if header_offset_32 is not None:
        if 8 <= remaining and header_offset_32 == 0xFFFFFFFF:
            result.header_offset = _u64(payload, position)
            position += 8
            remaining -= 8
    if disk_start_number_16 is not None:
        if 4 <= remaining and disk_start_number_16 == 0xFFFF:
            result.disk_start_number = _u32(payload, position)
            position += 4
            remaining -= 4

    if len(payload) != len(result.payload()):
        raise ZipError("could not read ZIP64 extra field")

    return result


class _LocalFileHeader:
    """Local file header."""

    def __init__(self) -> None:
        self.version_needed_to_extract = 0
        self.flags = 0
        self.method = 0
        self.last_mod_time = 0
        self.last_mod_date = 0
        self.crc32 = 0
        self.compressed_size = 0
        self.uncompressed_size = 0
        self.filename = b""
        self.extra = _ExtraField()
        self.start = 0
        self.end = 0

    @classmethod
    def parse(cls, data: bytes, offset: int) -> "_LocalFileHeader":
        header = cls()
        header.start = offset
        header.version_needed_to_extract = _u16(data, offset)
        header.flags = _u16(data, offset + 2)
        header.method = _u16(data, offset + 4)
        header.last_mod_time = _u16(data, offset + 6)
        header.last_mod_date = _u16(data, offset + 8)
        header.crc32 = _u32(data, offset + 10)
        header.compressed_size = _u32(data, offset + 14)
        header.uncompressed_size = _u32(data, offset + 18)
        filename_length = _u16(data, offset + 22)
        extra_length = _u16(data, offset + 24)

        header.filename = data[offset + 26 : offset + 26 + filename_length]
        if len(header.filename) != filename_length:
            raise ZipError("could not read local file header")

        extra_offset = offset + 26 + filename_length
        header.extra, end = _ExtraField.parse(
            data,
            extra_offset,
            extra_length,
            header.uncompressed_size,
            header.compressed_size,
        )
        header.end = end
        return header

    def write(self) -> bytes:
        extra = self.extra.write()
        filename = self.filename
        out = bytearray()
        out += _p16(self.version_needed_to_extract)
        out += _p16(self.flags)
        out += _p16(self.method)
        out += _p16(self.last_mod_time)
        out += _p16(self.last_mod_date)
        out += _p32(self.crc32)
        out += _p32(self.compressed_size)
        out += _p32(self.uncompressed_size)
        out += _p16(len(filename))
        out += _p16(len(extra))
        out += filename
        out += extra
        return bytes(out)


class _CentralDirectoryHeader:
    """Central directory header."""

    def __init__(self) -> None:
        self.version_made_by = 0
        self.version_needed_to_extract = 0
        self.flags = 0
        self.method = 0
        self.last_mod_time = 0
        self.last_mod_date = 0
        self.crc32 = 0
        self.compressed_size = 0
        self.uncompressed_size = 0
        self.disk_start_number = 0
        self.internal_file_attributes = 0
        self.external_file_attributes = 0
        self.header_offset = 0
        self.filename = b""
        self.extra = _ExtraField()
        self.file_comment = b""
        self.end = 0

    @classmethod
    def parse(cls, data: bytes, offset: int) -> "_CentralDirectoryHeader":
        header = cls()
        header.version_made_by = _u16(data, offset)
        header.version_needed_to_extract = _u16(data, offset + 2)
        header.flags = _u16(data, offset + 4)
        header.method = _u16(data, offset + 6)
        header.last_mod_time = _u16(data, offset + 8)
        header.last_mod_date = _u16(data, offset + 10)
        header.crc32 = _u32(data, offset + 12)
        header.compressed_size = _u32(data, offset + 16)
        header.uncompressed_size = _u32(data, offset + 20)
        filename_length = _u16(data, offset + 24)
        extra_length = _u16(data, offset + 26)
        file_comment_length = _u16(data, offset + 28)
        header.disk_start_number = _u16(data, offset + 30)
        header.internal_file_attributes = _u16(data, offset + 32)
        header.external_file_attributes = _u32(data, offset + 34)
        header.header_offset = _u32(data, offset + 38)

        header.filename = data[offset + 42 : offset + 42 + filename_length]
        if len(header.filename) != filename_length:
            raise ZipError("could not read central directory header")

        extra_offset = offset + 42 + filename_length
        header.extra, end = _ExtraField.parse(
            data,
            extra_offset,
            extra_length,
            header.uncompressed_size,
            header.compressed_size,
            header.header_offset,
            header.disk_start_number,
        )

        header.file_comment = data[end : end + file_comment_length]
        if len(header.file_comment) != file_comment_length:
            raise ZipError("could not read central directory header")

        header.end = end + file_comment_length
        return header

    def get_encryption(self) -> Encryption:
        if not self.flags & 1:
            return Encryption.NONE
        if self.method == 99 or (self.flags >> 6) & 1:
            return Encryption.UNSUPPORTED
        return Encryption.TRADITIONAL

    def write(self) -> bytes:
        extra = self.extra.write()
        out = bytearray()
        out += _p16(self.version_made_by)
        out += _p16(self.version_needed_to_extract)
        out += _p16(self.flags)
        out += _p16(self.method)
        out += _p16(self.last_mod_time)
        out += _p16(self.last_mod_date)
        out += _p32(self.crc32)
        out += _p32(self.compressed_size)
        out += _p32(self.uncompressed_size)
        out += _p16(len(self.filename))
        out += _p16(len(extra))
        out += _p16(len(self.file_comment))
        out += _p16(self.disk_start_number)
        out += _p16(self.internal_file_attributes)
        out += _p32(self.external_file_attributes)
        out += _p32(self.header_offset)
        out += self.filename
        out += extra
        out += self.file_comment
        return bytes(out)


def _find_central_directory_offset(data: bytes) -> int:
    """Locate the central directory, taking Zip64 extensions into account."""
    # find end of central directory signature
    comment_length = 0
    size = len(data)
    signature = None
    while True:
        position = size - 22 - comment_length
        if position < 0:
            raise ZipError("could not find end of central directory signature")
        if _u32(data, position) == _SIG_EOCD:
            signature = position
            break
        comment_length += 1
        if comment_length > 0xFFFF:
            raise ZipError("could not find end of central directory signature")

    record = signature + 4
    disk = _u16(data, record)
    central_directory_offset = _u32(data, record + 12)

    if disk != 0:
        raise ZipError("split zip archives are not supported")

    # look for Zip64 end of central directory locator
    locator = signature - 20
    if locator >= 0 and _u32(data, locator) == _SIG_ZIP64_LOCATOR:
        zip64_eocd_offset = _u64(data, locator + 8)

        if zip64_eocd_offset + 4 > size or _u32(data, zip64_eocd_offset) != _SIG_ZIP64_EOCD:
            raise ZipError("could not find Zip64 end of central directory record")

        version_needed_to_extract = _u16(data, zip64_eocd_offset + 14)
        central_directory_offset = _u64(data, zip64_eocd_offset + 48)

        if version_needed_to_extract >= 62:
            raise ZipError("central directory encryption is not supported")

    return central_directory_offset


class Zip:
    """Open a zip archive from its content."""

    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)
        self.central_directory_offset = _find_central_directory_offset(self._data)
        self._entries: Optional[List[Entry]] = None

    # -- entries -----------------------------------------------------------

    @property
    def entries(self) -> List[Entry]:
        if self._entries is None:
            self._entries = list(self._iter_entries())
        return self._entries

    def _iter_entries(self) -> Iterable[Entry]:
        data = self._data
        position = self.central_directory_offset

        while True:
            if position + 4 > len(data) or _u32(data, position) != _SIG_CENTRAL:
                return

            header = _CentralDirectoryHeader.parse(data, position + 4)
            position = header.end

            aes_extra = header.extra.find_aes()
            unicode_path = header.extra.find_unicode_path()
            zip64 = header.extra.find_zip64()

            name = header.filename
            if unicode_path is not None and len(unicode_path) >= 5:
                name_crc = _u32(unicode_path, 1)
                if (_crc32_of(header.filename)) == name_crc:
                    name = unicode_path[5:]

            method = header.method
            if aes_extra is not None:
                method = _u16(aes_extra, 5)

            offset = header.header_offset
            if zip64 is not None and zip64.header_offset is not None:
                offset = zip64.header_offset

            packed_size = header.compressed_size
            if zip64 is not None and zip64.compressed_size is not None:
                packed_size = zip64.compressed_size

            uncompressed_size = header.uncompressed_size
            if zip64 is not None and zip64.uncompressed_size is not None:
                uncompressed_size = zip64.uncompressed_size

            check_byte = (
                (header.last_mod_time >> 8) & 0xFF
                if (header.flags >> 3) & 1
                else (header.crc32 >> 24) & 0xFF
            )

            yield Entry(
                name=name,
                encryption=header.get_encryption(),
                compression=method,
                crc32=header.crc32,
                offset=offset,
                packed_size=packed_size,
                uncompressed_size=uncompressed_size,
                check_byte=check_byte,
            )

    def __len__(self) -> int:
        return len(self.entries)

    def __getitem__(self, key):
        if isinstance(key, int):
            try:
                return self.entries[key]
            except IndexError:
                raise ZipError(
                    f"found no entry at index {key} "
                    f"(maximum index for this archive is {len(self.entries) - 1})"
                ) from None

        target = os.fsencode(key) if isinstance(key, str) else key

        for entry in self.entries:
            if entry.name == target:
                return entry

        raise ZipError(f'found no entry named "{_decode(key)}"')

    # -- data --------------------------------------------------------------

    @staticmethod
    def check_encryption(entry: Entry, expected: Encryption) -> None:
        if entry.encryption is not expected:
            name = entry.name_text
            if entry.encryption is Encryption.NONE:
                raise ZipError(f'entry "{name}" is not encrypted')
            if expected is Encryption.NONE:
                raise ZipError(f'entry "{name}" is encrypted')
            raise ZipError(f'entry "{name}" is encrypted with an unsupported algorithm')

    def seek(self, entry: Entry) -> int:
        data = self._data
        position = entry.offset

        if _u32(data, position) != _SIG_LOCAL:
            raise ZipError("could not find local file header")

        name_size = _u16(data, position + 26)
        extra_size = _u16(data, position + 28)
        return position + 30 + name_size + extra_size

    def load(self, entry: Entry, count: Optional[int] = None) -> bytes:
        start = self.seek(entry)
        size = entry.packed_size if count is None else min(entry.packed_size, count)
        chunk = self._data[start : start + size]
        if len(chunk) != size:
            raise ZipError("could not read entry data")
        return chunk

    # -- rewriting ---------------------------------------------------------

    def _encrypted_entries(self) -> List[Tuple[int, int]]:
        """Offsets and packed sizes of traditionally encrypted entries."""
        by_offset = {}
        for entry in self.entries:
            if entry.encryption is Encryption.TRADITIONAL:
                # std::map::insert keeps the first inserted value for duplicate keys
                by_offset.setdefault(entry.offset, entry.packed_size)
        return sorted(by_offset.items())

    def change_keys(self, old_keys: Keys, new_keys: Keys, progress=None) -> bytes:
        """Return a copy of the archive re-encrypted with *new_keys*."""
        data = self._data
        encrypted = self._encrypted_entries()

        if progress is not None:
            progress.done = 0
            progress.total = len(encrypted)

        out = bytearray()
        position = 0

        for local_offset, packed_size in encrypted:
            if position < local_offset:
                out += data[position:local_offset]
                position = local_offset

            if _u32(data, position) != _SIG_LOCAL:
                raise ZipError("could not find local file header")

            header = _LocalFileHeader.parse(data, position + 4)
            out += _p32(_SIG_LOCAL)
            # copy the fixed part of the local file header (22 bytes after the signature)
            out += data[position + 4 : position + 26]

            # copy the file name and the extra field, keeping their length prefixes
            filename_length = _u16(data, position + 26)
            extra_length = _u16(data, position + 28)
            out += data[position + 26 : position + 30]
            out += data[position + 30 : position + 30 + filename_length + extra_length]
            position = header.end

            body = data[position : position + packed_size]
            if len(body) != packed_size:
                raise ZipError("could not read entry data")

            transformed = bytearray(packed_size)
            decrypt_keys = Keys(old_keys.x, old_keys.y, old_keys.z)
            encrypt_keys = Keys(new_keys.x, new_keys.y, new_keys.z)
            for i, c in enumerate(body):
                p = c ^ decrypt_keys.k
                transformed[i] = p ^ encrypt_keys.k
                decrypt_keys.update(p)
                encrypt_keys.update(p)

            out += transformed
            position += packed_size

            if progress is not None:
                progress.done += 1

        out += data[position:]
        return bytes(out)

    def decrypt(self, keys: Keys, progress=None) -> bytes:
        """Return a copy of the archive with encrypted entries deciphered."""
        data = self._data
        encrypted = self._encrypted_entries()

        if progress is not None:
            progress.done = 0
            progress.total = len(encrypted)

        out = bytearray()
        position = 0

        for local_offset, packed_size in encrypted:
            if position < local_offset:
                out += data[position:local_offset]
                position = local_offset

            if _u32(data, position) != _SIG_LOCAL:
                raise ZipError("could not find local file header")
            out += _p32(_SIG_LOCAL)
            position += 4

            file_header = _LocalFileHeader.parse(data, position)
            position = file_header.end

            zip64_extra = file_header.extra.find_zip64()
            file_header.flags &= ~1
            if zip64_extra is not None and zip64_extra.compressed_size is not None:
                zip64_extra.compressed_size -= ENCRYPTION_HEADER_SIZE
            elif ENCRYPTION_HEADER_SIZE <= file_header.compressed_size:
                file_header.compressed_size -= ENCRYPTION_HEADER_SIZE
            out += file_header.write()

            body = data[position : position + packed_size]
            if len(body) != packed_size:
                raise ZipError("could not read entry data")
            position += packed_size

            out += _decipher_bytes(body, keys, ENCRYPTION_HEADER_SIZE)

            # transform data descriptor
            descriptor_size = 0
            if (file_header.flags >> 3) & 1:
                crc32_or_signature = _u32(data, position)
                out += _p32(crc32_or_signature)
                position += 4
                descriptor_size += 4

                if crc32_or_signature == _SIG_DATA_DESCRIPTOR:
                    actual_crc32 = _u32(data, position)
                    out += _p32(actual_crc32)
                    position += 4
                    descriptor_size += 4

                if zip64_extra is not None:
                    out += _p64(_u64(data, position) - ENCRYPTION_HEADER_SIZE)
                    out += _p64(_u64(data, position + 8))
                    position += 16
                    descriptor_size += 16
                else:
                    out += _p32(_u32(data, position) - ENCRYPTION_HEADER_SIZE)
                    out += _p32(_u32(data, position + 4))
                    position += 8
                    descriptor_size += 8

            if progress is not None:
                progress.done += 1

        if position < self.central_directory_offset:
            out += data[position : self.central_directory_offset]
            position = self.central_directory_offset

        def translate(offset: int) -> int:
            count = sum(1 for local_offset, _ in encrypted if local_offset < offset)
            return offset - count * ENCRYPTION_HEADER_SIZE

        # update metadata in central directory
        signature = _u32(data, position) if position + 4 <= len(data) else 0

        while position + 4 <= len(data) and signature == _SIG_CENTRAL:
            out += _p32(signature)
            header = _CentralDirectoryHeader.parse(data, position + 4)
            position = header.end

            zip64_extra = header.extra.find_zip64()
            if header.get_encryption() is Encryption.TRADITIONAL:
                header.flags &= ~1
                if zip64_extra is not None and zip64_extra.compressed_size is not None:
                    zip64_extra.compressed_size -= ENCRYPTION_HEADER_SIZE
                elif ENCRYPTION_HEADER_SIZE <= header.compressed_size:
                    header.compressed_size -= ENCRYPTION_HEADER_SIZE

            if zip64_extra is not None and zip64_extra.header_offset is not None:
                zip64_extra.header_offset = translate(zip64_extra.header_offset)
            else:
                header.header_offset = translate(header.header_offset)

            out += header.write()
            signature = _u32(data, position) if position + 4 <= len(data) else 0

        is_zip64 = False
        if position + 4 <= len(data) and signature == _SIG_ZIP64_EOCD:
            out += _p32(signature)
            is_zip64 = True
            position += 4

            size_of_zip64_eocd = _u64(data, position)
            out += _p64(size_of_zip64_eocd)
            position += 8

            out += data[position : position + 36]
            position += 36

            eocd_start_offset = _u64(data, position)
            out += _p64(translate(eocd_start_offset))
            position += 8

            if 44 < size_of_zip64_eocd:
                extra_size = size_of_zip64_eocd - 44
                out += data[position : position + extra_size]
                position += extra_size

            if _u32(data, position) != _SIG_ZIP64_LOCATOR:
                raise ZipError("could not find Zip64 end of central directory locator")
            out += _p32(_SIG_ZIP64_LOCATOR)
            position += 4

            out += data[position : position + 4]
            position += 4

            zip64_eocd_start_offset = _u64(data, position)
            out += _p64(translate(zip64_eocd_start_offset))
            position += 8

            out += data[position : position + 4]
            position += 4

            signature = _u32(data, position) if position + 4 <= len(data) else 0

        if signature != _SIG_EOCD:
            raise ZipError("could not find end of central directory record")
        out += _p32(_SIG_EOCD)
        position += 4

        out += data[position : position + 12]
        position += 12

        eocd_offset = _u32(data, position)
        if not is_zip64 or eocd_offset != 0xFFFFFFFF:
            eocd_offset = translate(eocd_offset)
        out += _p32(eocd_offset)
        position += 4

        out += data[position:]
        return bytes(out)


def _crc32_of(data: bytes) -> int:
    """CRC32 of *data* as computed by the reference code (no final inversion)."""
    from .tables import CRC_TABLE

    crc = 0xFFFFFFFF
    for byte in data:
        crc = (crc >> 8) ^ CRC_TABLE[(crc & 0xFF) ^ byte]
    return crc ^ 0xFFFFFFFF


def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _decipher_bytes(data: bytes, keys: Keys, discard: int) -> bytes:
    """Decipher *data* with *keys*, discarding the first *discard* bytes."""
    working = Keys(keys.x, keys.y, keys.z)

    for byte in data[:discard]:
        working.update(byte ^ working.k)

    out = bytearray()
    for byte in data[discard:]:
        p = byte ^ working.k
        working.update(p)
        out.append(p)
    return bytes(out)


def decipher(data: bytes, size: int, discard: int, keys: Keys) -> bytes:
    """Decipher at most *size* bytes from *data*, discarding the first *discard*."""
    chunk = data[:size]
    return _decipher_bytes(chunk, keys, discard)
