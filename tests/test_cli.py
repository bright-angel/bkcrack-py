"""End-to-end tests for the command line interface."""

from __future__ import annotations

import pytest

from bkcrack.cli import main
from bkcrack.keys import Keys
from bkcrack.ziparchive import Encryption, Zip


def encrypt(plaintext: bytes, password: str, header: bytes = bytes(12)) -> bytes:
    """Produce a ZipCrypto ciphertext (encryption header followed by data)."""
    keys = Keys.from_password(password)
    out = bytearray()

    for byte in header:
        out.append(byte ^ keys.k)
        keys.update(byte)

    for byte in plaintext:
        out.append(byte ^ keys.k)
        keys.update(byte)

    return bytes(out)


def run(capsys, *args: str) -> tuple:
    """Run the CLI in process and return the exit code and the output lines."""
    code = main(list(args))
    captured = capsys.readouterr()
    return code, captured.out


def test_version(capsys):
    code, out = run(capsys, "--version")

    assert code == 0
    assert out.strip() == "bkcrack 1.8.1 - 2025-10-25"


def test_help(capsys):
    code, out = run(capsys, "-h")

    assert code == 0
    assert "usage: bkcrack [options]" in out
    assert "-x, --extra <offset> <data>" in out
    assert "Show this help and exit" in out


def test_unknown_option(capsys):
    code, out = run(capsys, "--bogus")

    assert code == 1
    assert "Arguments error: unknown option --bogus." in out
    assert "Run 'bkcrack -h' for help." in out


def test_missing_file(capsys, tmp_path):
    code, out = run(capsys, "-c", str(tmp_path / "missing.bin"), "-p", str(tmp_path / "missing.txt"))

    assert code == 1
    assert "File error: could not open input file" in out


def test_list_archive(capsys, data_dir):
    code, out = run(capsys, "-L", str(data_dir / "zipcrypto.zip"))

    assert code == 0
    lines = out.splitlines()
    assert lines[0] == "bkcrack 1.8.1 - 2025-10-25"
    assert lines[1] == f"Archive: {data_dir / 'zipcrypto.zip'}"
    assert lines[2] == "Index Encryption Compression CRC32    Uncompressed  Packed size Name"
    assert lines[3] == "----- ---------- ----------- -------- ------------ ------------ ----------------"
    assert lines[4] == "    0 ZipCrypto  Store       1ca08acd          208          220 store.txt"
    assert lines[5] == "    1 ZipCrypto  Deflate     45e207a8          260           83 deflate.txt"


def test_list_example_archive(capsys, example_archive):
    code, out = run(capsys, "-L", str(example_archive))

    assert code == 0
    lines = out.splitlines()
    assert lines[4] == "    0 ZipCrypto  Deflate     7ca9f10a        54799        54700 advice.jpg"
    assert lines[5] == "    1 ZipCrypto  Store       a99f1d0d         1265         1277 spiral.svg"


def test_internal_representation_for_password(capsys):
    code, out = run(capsys, "--password", "password")

    assert code == 0
    assert 'Internal representation for password "password": ea9b4e4d ba789085 5ff8707d' in out


def test_decipher_entry(capsys, tmp_path, data_dir):
    output = tmp_path / "store.txt"
    code, out = run(
        capsys,
        "-C", str(data_dir / "zipcrypto.zip"),
        "-c", "store.txt",
        "-k", "ea9b4e4d", "ba789085", "5ff8707d",
        "-d", str(output),
    )

    assert code == 0
    assert "Writing deciphered data" in out
    assert "Wrote deciphered data (not compressed)." in out
    assert output.read_bytes().startswith(b"store A store B")


def test_decipher_with_keep_header(capsys, tmp_path, data_dir):
    output = tmp_path / "store.txt"
    code, out = run(
        capsys,
        "-C", str(data_dir / "zipcrypto.zip"),
        "-c", "store.txt",
        "-k", "ea9b4e4d", "ba789085", "5ff8707d",
        "-d", str(output),
        "--keep-header",
    )

    assert code == 0
    assert "Writing deciphered data" in out
    assert "with encryption header" in out
    assert len(output.read_bytes()) == 220


def test_decipher_file(capsys, tmp_path, data_dir):
    cipher = tmp_path / "store.bin"
    plain = tmp_path / "store.txt"
    cipher.write_bytes(encrypt(b"store A store B", "password"))

    code, out = run(
        capsys,
        "-c", str(cipher),
        "-k", "ea9b4e4d", "ba789085", "5ff8707d",
        "-d", str(plain),
    )

    assert code == 0
    assert plain.read_bytes() == b"store A store B"
    assert "Wrote deciphered data." in out


def test_decrypt_archive(capsys, tmp_path, data_dir):
    output = tmp_path / "plain.zip"
    code, out = run(
        capsys,
        "-C", str(data_dir / "zipcrypto.zip"),
        "-k", "ea9b4e4d", "ba789085", "5ff8707d",
        "-D", str(output),
    )

    assert code == 0
    assert f"Writing decrypted archive {output}" in out

    archive = Zip(output.read_bytes())
    assert [entry.name for entry in archive.entries] == [b"store.txt", b"deflate.txt"]
    assert all(entry.encryption is Encryption.NONE for entry in archive.entries)
    # the decrypted entries hold the original content
    assert archive.load(archive["store.txt"]).startswith(b"store A store B")


def test_change_password(capsys, tmp_path, data_dir):
    output = tmp_path / "new.zip"
    code, out = run(
        capsys,
        "-C", str(data_dir / "zipcrypto.zip"),
        "-k", "ea9b4e4d", "ba789085", "5ff8707d",
        "-U", str(output), "new_password",
    )

    assert code == 0
    assert f'Writing unlocked archive {output} with password "new_password"' in out
    assert "Wrote unlocked archive." in out

    # the new archive must be readable with the new password
    archive = Zip(output.read_bytes())
    entry = archive["store.txt"]
    assert entry.encryption is Encryption.TRADITIONAL

    start = archive.seek(entry)
    deciphered = _decipher_with(archive._data[start:], "new_password", 12)
    assert deciphered.startswith(b"store A")


def test_change_keys(capsys, tmp_path, data_dir):
    output = tmp_path / "new.zip"
    code, out = run(
        capsys,
        "-C", str(data_dir / "zipcrypto.zip"),
        "-k", "ea9b4e4d", "ba789085", "5ff8707d",
        "--change-keys", str(output), "11223344", "55667788", "99aabbcc",
    )

    assert code == 0
    assert f"Writing unlocked archive {output} with keys 11223344 55667788 99aabbcc" in out
    assert "Wrote unlocked archive." in out

    archive = Zip(output.read_bytes())
    start = archive.seek(archive["store.txt"])
    key_bytes = bytes.fromhex("112233445566778899aabbcc")
    keys = Keys(int.from_bytes(key_bytes[0:4], "big"), int.from_bytes(key_bytes[4:8], "big"), int.from_bytes(key_bytes[8:12], "big"))
    data = archive._data[start:]
    out_bytes = bytearray()
    for byte in data:
        plain = byte ^ keys.k
        keys.update(plain)
        out_bytes.append(plain)
    assert bytes(out_bytes[12:]).startswith(b"store A")


def _decipher_with(data: bytes, password: str, discard: int) -> bytes:
    keys = Keys.from_password(password)
    out = bytearray()
    for byte in data[:discard]:
        keys.update(byte ^ keys.k)
    for byte in data[discard:]:
        plain = byte ^ keys.k
        keys.update(plain)
        out.append(plain)
    return bytes(out)


@pytest.mark.slow
def test_attack_with_checkpoint(capsys, tmp_path):
    """Run the attack through the CLI, resuming close to the solution.

    Searching all candidates from scratch takes minutes in Python, so the
    checkpoint is computed with the library first.  Everything else (loading the
    data, the Z reduction, the attack and the output) goes through the CLI.
    """
    plaintext = b"The quick brown fox jumps over the lazy dog"
    plain = tmp_path / "plain.bin"
    cipher = tmp_path / "cipher.bin"
    plain.write_bytes(plaintext)
    cipher.write_bytes(encrypt(plaintext, "password"))

    checkpoint = _solution_checkpoint(cipher.read_bytes(), plaintext)

    code, out = run(
        capsys,
        "-c", str(cipher),
        "-p", str(plain),
        "-j", "1",
        "--continue-attack", str(checkpoint),
    )

    assert code == 0
    assert "Z reduction using" in out
    assert "Attack on" in out
    assert "ea9b4e4d ba789085 5ff8707d" in out
    assert "Found a solution. Stopping." in out


def _solution_checkpoint(cipher: bytes, plaintext: bytes) -> int:
    """Return the position of the real Z candidate in the reduced list."""
    from bkcrack.constants import mask
    from bkcrack.progress import Progress
    from bkcrack.zreduction import Zreduction

    keystream = bytes(c ^ p for c, p in zip(cipher[12:], plaintext))
    reduction = Zreduction(keystream)
    reduction.reduce(Progress())
    reduction.generate()

    keys = Keys.from_password("password")
    for byte in cipher[:12]:
        keys.update(byte ^ keys.k)
    for byte in plaintext[: reduction.index]:
        keys.update(byte)

    return reduction.candidates.index(keys.z & mask(2, 32))


def test_password_recovery(capsys):
    code, out = run(capsys, "-k", "9bcb20c6", "10a97ca5", "103c0614", "-b", "?p", "-l", "8")

    assert code == 0
    assert "as bytes: 5f 53 23 63 72 33 74 21" in out
    assert "as text: _S#cr3t!" in out


def test_mask_recovery(capsys):
    code, out = run(capsys, "-k", "c80f5189", "ce16bd43", "38247eb5", "-m", "Lorem ipsum dolor sit amet")

    assert code == 0
    assert "as text: Lorem ipsum dolor sit amet" in out


def test_password_recovery_failure(capsys):
    code, out = run(capsys, "-k", "f1f9ab49", "8574a6fd", "cb99758d", "-b", "?d", "-l", "6")

    assert code == 1
    assert "Could not recover password" in out
