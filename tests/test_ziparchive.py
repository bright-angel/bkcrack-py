"""Tests for the zip archive handling, ported from ``Zip.test.cpp``."""

from __future__ import annotations

import pytest

from bkcrack.errors import ZipError
from bkcrack.keys import Keys
from bkcrack.progress import Progress
from bkcrack.ziparchive import Compression, Encryption, Zip, decipher


def open_zip(path) -> Zip:
    return Zip(path.read_bytes())


def test_parse_empty_zip(data_dir):
    archive = open_zip(data_dir / "empty.zip")
    assert archive.entries == []


def test_fail_to_parse_non_zip_file(data_dir):
    with pytest.raises(ZipError) as info:
        open_zip(data_dir / "make_test_data.sh")
    assert "could not find end of central directory signature" in str(info.value)


def test_parse_plain_zip(data_dir):
    archive = open_zip(data_dir / "plain.zip")
    assert len(archive.entries) == 2

    store, deflate = archive.entries
    assert store.name == b"store.txt"
    assert store.encryption is Encryption.NONE
    assert store.compression == Compression.STORE
    assert store.crc32 == 0x1CA08ACD
    assert store.offset == 0
    assert store.packed_size == 208
    assert store.uncompressed_size == 208
    assert store.check_byte == 0x1C

    assert deflate.name == b"deflate.txt"
    assert deflate.encryption is Encryption.NONE
    assert deflate.compression == Compression.DEFLATE
    assert deflate.crc32 == 0x45E207A8
    assert deflate.offset == 247
    assert deflate.packed_size == 71
    assert deflate.uncompressed_size == 260
    assert deflate.check_byte == 0x45


def test_parse_zipcrypto_zip(data_dir):
    archive = open_zip(data_dir / "zipcrypto.zip")
    assert len(archive.entries) == 2

    store, deflate = archive.entries
    assert store.name == b"store.txt"
    assert store.encryption is Encryption.TRADITIONAL
    assert store.compression == Compression.STORE
    assert store.crc32 == 0x1CA08ACD
    assert store.offset == 0
    assert store.packed_size == 220
    assert store.uncompressed_size == 208
    assert store.check_byte == 0xAB

    assert deflate.name == b"deflate.txt"
    assert deflate.encryption is Encryption.TRADITIONAL
    assert deflate.compression == Compression.DEFLATE
    assert deflate.crc32 == 0x45E207A8
    assert deflate.offset == 275
    assert deflate.packed_size == 83
    assert deflate.uncompressed_size == 260
    assert deflate.check_byte == 0xAB


def test_parse_zip64_zip(data_dir):
    archive = open_zip(data_dir / "zip64.zip")
    assert len(archive.entries) == 2

    store, deflate = archive.entries
    assert store.name == b"store.txt"
    assert store.encryption is Encryption.NONE
    assert store.compression == Compression.STORE
    assert store.crc32 == 0x1CA08ACD
    assert store.offset == 0
    assert store.packed_size == 208
    assert store.uncompressed_size == 208
    assert store.check_byte == 0x1C

    assert deflate.name == b"deflate.txt"
    assert deflate.encryption is Encryption.NONE
    assert deflate.compression == Compression.DEFLATE
    assert deflate.crc32 == 0x45E207A8
    assert deflate.offset == 267
    assert deflate.packed_size == 71
    assert deflate.uncompressed_size == 260
    assert deflate.check_byte == 0x45


def test_parse_zip64_zipcrypto_zip(data_dir):
    archive = open_zip(data_dir / "zip64-zipcrypto.zip")
    assert len(archive.entries) == 2

    store, deflate = archive.entries
    assert store.name == b"store.txt"
    assert store.encryption is Encryption.TRADITIONAL
    assert store.compression == Compression.STORE
    assert store.crc32 == 0x1CA08ACD
    assert store.offset == 0
    assert store.packed_size == 220
    assert store.uncompressed_size == 208
    assert store.check_byte == 0xAB

    assert deflate.name == b"deflate.txt"
    assert deflate.encryption is Encryption.TRADITIONAL
    assert deflate.compression == Compression.DEFLATE
    assert deflate.crc32 == 0x45E207A8
    assert deflate.offset == 303
    assert deflate.packed_size == 83
    assert deflate.uncompressed_size == 260
    assert deflate.check_byte == 0xAB


def test_parse_aes256_zip(data_dir):
    archive = open_zip(data_dir / "aes256.zip")
    assert len(archive.entries) == 2

    deflate, store = archive.entries
    assert deflate.name == b"deflate.txt"
    assert deflate.encryption is Encryption.UNSUPPORTED
    assert deflate.compression == Compression.DEFLATE
    assert deflate.crc32 == 0x00000000
    assert deflate.offset == 0
    assert deflate.packed_size == 95
    assert deflate.uncompressed_size == 260
    assert deflate.check_byte == 0x00

    assert store.name == b"store.txt"
    assert store.encryption is Encryption.UNSUPPORTED
    assert store.compression == Compression.STORE
    assert store.crc32 == 0x00000000
    assert store.offset == 147
    assert store.packed_size == 236
    assert store.uncompressed_size == 208
    assert store.check_byte == 0x00


def test_get_entry_by_name(data_dir):
    archive = open_zip(data_dir / "plain.zip")

    assert archive["store.txt"].name == b"store.txt"
    assert archive["deflate.txt"].name == b"deflate.txt"

    with pytest.raises(ZipError) as info:
        archive["does not exist"]
    assert 'found no entry named "does not exist"' in str(info.value)


def test_get_entry_by_index(data_dir):
    archive = open_zip(data_dir / "plain.zip")

    assert archive[0].name == b"store.txt"
    assert archive[1].name == b"deflate.txt"

    with pytest.raises(ZipError) as info:
        archive[2]
    assert "found no entry at index 2 (maximum index for this archive is 1)" in str(info.value)


def test_check_encryption():
    from bkcrack.ziparchive import Entry

    entry = Entry(
        name=b"test",
        encryption=Encryption.NONE,
        compression=0,
        crc32=0,
        offset=0,
        packed_size=0,
        uncompressed_size=0,
        check_byte=0,
    )

    Zip.check_encryption(entry, Encryption.NONE)
    with pytest.raises(ZipError) as info:
        Zip.check_encryption(entry, Encryption.TRADITIONAL)
    assert 'entry "test" is not encrypted' in str(info.value)

    entry.encryption = Encryption.TRADITIONAL
    with pytest.raises(ZipError) as info:
        Zip.check_encryption(entry, Encryption.NONE)
    assert 'entry "test" is encrypted' in str(info.value)
    Zip.check_encryption(entry, Encryption.TRADITIONAL)

    entry.encryption = Encryption.UNSUPPORTED
    with pytest.raises(ZipError) as info:
        Zip.check_encryption(entry, Encryption.NONE)
    assert 'entry "test" is encrypted' in str(info.value)
    with pytest.raises(ZipError) as info:
        Zip.check_encryption(entry, Encryption.TRADITIONAL)
    assert 'entry "test" is encrypted with an unsupported algorithm' in str(info.value)


def test_seek_to_entry_data(data_dir):
    archive = open_zip(data_dir / "plain.zip")
    entry = archive["store.txt"]

    position = archive.seek(entry)
    assert position == 39
    assert archive._data[position : position + 7] == b"store A"


def test_load_entry_data(data_dir):
    archive = open_zip(data_dir / "plain.zip")
    entry = archive["store.txt"]

    data = archive.load(entry)
    assert len(data) == 208
    assert data[:1] == b"s"
    assert data[-1:] == b"\n"

    assert archive.load(entry, 7) == b"store A"


def test_change_keys(data_dir):
    archive = open_zip(data_dir / "zipcrypto.zip")

    progress = Progress()
    updated = archive.change_keys(Keys.from_password("password"), Keys.from_password("new_password"), progress)
    assert progress.done == 2
    assert progress.total == 2

    new_zip = Zip(updated)
    store = new_zip["store.txt"]
    deflate = new_zip["deflate.txt"]

    assert store.name == b"store.txt"
    assert store.encryption is Encryption.TRADITIONAL
    assert store.compression == Compression.STORE
    assert store.crc32 == 0x1CA08ACD
    assert store.offset == 0
    assert store.packed_size == 220
    assert store.uncompressed_size == 208
    assert store.check_byte == 0xAB

    assert deflate.name == b"deflate.txt"
    assert deflate.encryption is Encryption.TRADITIONAL
    assert deflate.compression == Compression.DEFLATE
    assert deflate.crc32 == 0x45E207A8
    assert deflate.offset == 275
    assert deflate.packed_size == 83
    assert deflate.uncompressed_size == 260
    assert deflate.check_byte == 0xAB

    start = new_zip.seek(store)
    # the 12-byte encryption header is skipped except its last byte
    assert (
        decipher(updated[start : start + 12 + 7], 12 + 7, 11, Keys.from_password("new_password"))
        == b"\xabstore A"
    )


def test_decrypt_zipcrypto_zip(data_dir):
    archive = open_zip(data_dir / "zipcrypto.zip")

    progress = Progress()
    decrypted = archive.decrypt(Keys.from_password("password"), progress)
    assert progress.done == 2
    assert progress.total == 2

    new_zip = Zip(decrypted)
    store = new_zip["store.txt"]
    deflate = new_zip["deflate.txt"]

    assert store.name == b"store.txt"
    assert store.encryption is Encryption.NONE
    assert store.compression == Compression.STORE
    assert store.crc32 == 0x1CA08ACD
    assert store.offset == 0
    assert store.packed_size == 208
    assert store.uncompressed_size == 208

    assert deflate.name == b"deflate.txt"
    assert deflate.encryption is Encryption.NONE
    assert deflate.compression == Compression.DEFLATE
    assert deflate.crc32 == 0x45E207A8
    assert deflate.offset == 263
    assert deflate.packed_size == 71
    assert deflate.uncompressed_size == 260

    assert new_zip.load(store, 7) == b"store A"


def test_decrypt_zip64_zipcrypto_zip(data_dir):
    archive = open_zip(data_dir / "zip64-zipcrypto.zip")

    progress = Progress()
    decrypted = archive.decrypt(Keys.from_password("password"), progress)
    assert progress.done == 2
    assert progress.total == 2

    new_zip = Zip(decrypted)
    store = new_zip["store.txt"]
    deflate = new_zip["deflate.txt"]

    assert store.name == b"store.txt"
    assert store.encryption is Encryption.NONE
    assert store.compression == Compression.STORE
    assert store.offset == 0
    assert store.packed_size == 208
    assert store.uncompressed_size == 208

    assert deflate.name == b"deflate.txt"
    assert deflate.encryption is Encryption.NONE
    assert deflate.compression == Compression.DEFLATE
    assert deflate.offset == 291
    assert deflate.packed_size == 71
    assert deflate.uncompressed_size == 260

    assert new_zip.load(store, 7) == b"store A"


def test_decrypt_aes256_zip_does_nothing(data_dir):
    content = (data_dir / "aes256.zip").read_bytes()
    archive = Zip(content)

    progress = Progress()
    decrypted = archive.decrypt(Keys.from_password("password"), progress)
    assert progress.done == 0
    assert progress.total == 0
    assert decrypted == content


def test_decipher(data_dir):
    archive = open_zip(data_dir / "zipcrypto.zip")
    start = archive.seek(archive["store.txt"])

    data = archive._data[start : start + 12 + 23]
    assert decipher(data, 12 + 23, 12, Keys.from_password("password")) == b"store A store B store C"
