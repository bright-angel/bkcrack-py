"""Command line interface, mirroring ``main.cpp``."""

from __future__ import annotations

import contextlib
import os
import signal
import sys
import time
from typing import List, Optional, Sequence, Union

from . import __version__, __version_date__
from .arguments import Arguments, LengthInterval
from .attack import attack
from .console_progress import ConsoleProgress
from .errors import ArgumentsError, BaseError
from .file import open_input, open_output
from .keys import Keys
from .password import recover_password, recover_password_for_mask
from .progress import State
from .ziparchive import Compression, Encryption, Zip, decipher
from .zreduction import Zreduction

__all__ = ["main", "usage"]

USAGE = """usage: bkcrack [options]
Crack legacy zip encryption with Biham and Kocher's known plaintext attack.

Options to get the internal password representation:
 -c, --cipher-file <file>    Zip entry or file on disk containing ciphertext
     --cipher-index <index>  Index of the zip entry containing ciphertext
 -C, --cipher-zip <archive>  Zip archive containing the ciphertext entry

 -p, --plain-file <file>     Zip entry or file on disk containing plaintext
     --plain-index <index>   Index of the zip entry containing plaintext
 -P, --plain-zip <archive>   Zip archive containing the plaintext entry
 -t, --truncate <size>       Maximum number of bytes of plaintext to load
 -o, --offset <offset>       Known plaintext offset relative to ciphertext
                              without encryption header (may be negative)
 -x, --extra <offset> <data> Additional plaintext in hexadecimal starting
                              at the given offset (may be negative)
     --ignore-check-byte     Do not automatically use ciphertext's check byte
                              as known plaintext

     --continue-attack <checkpoint>
        Starting point of the attack. Useful to continue a previous
        non-exhaustive or interrupted attack.

     --password <password>
        Password from which to derive the internal password representation.
        Useful for testing purposes and advanced scenarios such as reverting
        the effect of the --change-password command.

Options to use the internal password representation:
 -k, --keys <X> <Y> <Z>      Internal password representation as three 32-bits
                              integers in hexadecimal (requires -d, -D, -U,
                              --change-keys, --bruteforce or --mask)

 -d, --decipher <file>       File to write the deciphered data (requires -c)
     --keep-header           Write the encryption header at the beginning of
                              deciphered data instead of discarding it

 -D, --decrypt <archive>
        Create a copy of the encrypted zip archive with deciphered entries,
        removing the password protection (requires -C)

 -U, --change-password <archive> <password>
        Create a copy of the encrypted zip archive with the password set to the
        given new password (requires -C)

     --change-keys <archive> <X> <Y> <Z>
        Create a copy of the encrypted zip archive using the given new internal
        password representation (requires -C)

 -b, --bruteforce <charset>
        Try to recover the password or an equivalent one by generating and
        testing password candidates using characters in the given charset.
        The charset is a sequence of characters or shortcuts for predefined
        charsets listed below. Example: ?l?d-.@

          ?l lowercase letters              abcdefghijklmnopqrstuvwxyz
          ?u uppercase letters              ABCDEFGHIJKLMNOPQRSTUVWXYZ
          ?d decimal digits                 0123456789
          ?s special characters              !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~
          ?a alpha-numerical characters     (same as ?l?u?d)
          ?p printable ASCII characters     (same as ?l?u?d?s)
          ?b all bytes                      (0x00 - 0xff)

 -l, --length [ <min>..<max> | <min>.. | ..<max> | <length> ]
        Length interval or exact length of password candidates to generate and
        test during password recovery (requires --bruteforce)

 -r, --recover-password [ <min>..<max> | <min>.. | ..<max> | <max> ] <charset>
        Shortcut for --length and --bruteforce options

 -m, --mask <mask>
        Try to recover the password or an equivalent one by generating and
        testing password candidates following the given mask.
        The mask is a sequence of fixed characters or character sets (either
        predefined or custom charsets). Example: -m ?u?l?l?l?l-?d?d?d?d

 -s, --charset <identifier> <charset>
        Define a custom character set. Example: -s h ?dabcdef

     --continue-recovery <checkpoint>
        Starting point of the password recovery. Useful to continue a previous
        non-exhaustive or interrupted password recovery.

Other options:
 -j, --jobs <count>          Number of threads to use for parallel operations
 -e, --exhaustive            Exhaustively look for all solutions (keys or
                              passwords) instead of stopping after the first
                              solution is found
 -L, --list <archive>        List entries in a zip archive and exit
     --version               Show version information and exit
 -h, --help                  Show this help and exit"""

usage = USAGE

_COMPRESSION_DESCRIPTIONS = {
    Compression.STORE: "Store",
    Compression.SHRINK: "Shrink",
    Compression.IMPLODE: "Implode",
    Compression.DEFLATE: "Deflate",
    Compression.DEFLATE64: "Deflate64",
    Compression.BZIP2: "BZip2",
    Compression.LZMA: "LZMA",
    Compression.ZSTANDARD: "Zstandard",
    Compression.MP3: "MP3",
    Compression.XZ: "XZ",
    Compression.JPEG: "JPEG",
    Compression.WAVPACK: "WavPack",
    Compression.PPMD: "PPMd",
}


LINE_END = os.linesep.encode()


@contextlib.contextmanager
def _interruptible(progress):
    """Turn SIGINT into a cancellation of *progress*, like ``SigintHandler``."""
    previous = signal.getsignal(signal.SIGINT)

    def handler(signum, frame):
        progress.state = State.CANCELED

    try:
        signal.signal(signal.SIGINT, handler)
    except ValueError:  # pragma: no cover - not running in the main thread
        yield
        return

    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def _write(*parts: Union[str, bytes]) -> None:
    """Write a line made of text and raw bytes, like a C++ output stream would."""
    data = b"".join(part.encode("utf-8") if isinstance(part, str) else part for part in parts)
    data += LINE_END

    stream = sys.stdout
    buffer = getattr(stream, "buffer", None)
    if buffer is None:  # pragma: no cover - text only streams
        stream.write(data.decode("utf-8", "replace"))
        stream.flush()
    else:
        stream.flush()
        buffer.write(data)
        buffer.flush()


def _timestamp() -> str:
    """Return the current local time formatted like C++ ``std::put_time("%T")``."""
    return time.strftime("%H:%M:%S")


def _encryption_description(encryption: Encryption) -> str:
    if encryption is Encryption.NONE:
        return "None"
    if encryption is Encryption.TRADITIONAL:
        return "ZipCrypto"
    return "Other"


def _compression_description(compression: int) -> str:
    try:
        return _COMPRESSION_DESCRIPTIONS[Compression(compression)]
    except ValueError:
        return f"Other ({compression})"


def _hex_dump(value: bytes) -> str:
    return "".join(f"{byte:02x}" for byte in value)


def _keys_to_text(keys: Keys) -> str:
    return f"{keys.x:08x} {keys.y:08x} {keys.z:08x}"


def list_entries(archive_filename: str) -> None:
    """Print the entries of *archive_filename* like ``-L`` does."""
    with open_input(archive_filename) as stream:
        archive = Zip(stream.read())

    print(f"Archive: {archive_filename}")
    print("Index Encryption Compression CRC32    Uncompressed  Packed size Name")
    print("----- ---------- ----------- -------- ------------ ------------ ----------------")

    for index, entry in enumerate(archive.entries):
        encryption = _encryption_description(entry.encryption)
        compression = _compression_description(entry.compression)
        _write(
            f"{index:>5} {encryption:<10} {compression:<11} {entry.crc32:08x} "
            f"{entry.uncompressed_size:>12} {entry.packed_size:>12} ",
            entry.name,
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the command line interface and return the process exit code."""
    if argv is None:
        argv = sys.argv[1:]

    print(f"bkcrack {__version__} - {__version_date__}")

    try:
        args = Arguments(argv)

        if args.help:
            print(USAGE)
            return 0

        if args.version:
            # version information was already printed, nothing else to do
            return 0

        if args.info_archive is not None:
            list_entries(args.info_archive)
            return 0

        keysvec: List[Keys] = []
        if args.keys is not None:
            keysvec.append(args.keys)
        elif args.password is not None:
            keysvec.append(Keys.from_password(args.password))
            _write(
                b'Internal representation for password "',
                args.password,
                b'": ',
                _keys_to_text(keysvec[-1]),
            )
        else:
            # find keys from known plaintext
            data = args.load_data()

            # generate and reduce Zi[10,32) values
            zr = Zreduction(data.keystream)
            if len(data.keystream) > 8:
                print(
                    f"[{_timestamp()}] Z reduction using "
                    f"{len(data.keystream) - 8} bytes of known plaintext"
                )
                with ConsoleProgress() as progress:
                    zr.reduce(progress)

            # generate Zi[2,32) values
            zr.generate()

            # carry out the attack on the remaining Zi[2,32) values
            print(
                f"[{_timestamp()}] Attack on {len(zr.candidates)} Z values "
                f"at index {data.offset + zr.index - 12}"
            )

            start = args.attack_start
            with ConsoleProgress() as progress, _interruptible(progress):
                keysvec, restart = attack(
                    data,
                    zr.candidates,
                    start,
                    zr.index,
                    args.jobs,
                    args.exhaustive,
                    progress,
                )
                state = progress.state

            if state is not State.NORMAL:
                if state is State.CANCELED:
                    print("Operation interrupted by user.")
                elif state is State.EARLY_EXIT:
                    print("Found a solution. Stopping.")

                if restart < len(zr.candidates):
                    print(
                        "You may resume the attack with the option: "
                        f"--continue-attack {restart}"
                    )

            # print the keys
            print(f"[{_timestamp()}] ", end="")
            if not keysvec:
                print("Could not find the keys.")
                return 1

            print("Keys")
            for keys in keysvec:
                print(_keys_to_text(keys))

        # From there, keysvec is not empty.
        keys = keysvec[0]
        if (
            args.deciphered_file
            or args.change_password
            or args.change_keys
            or args.bruteforce
        ) and len(keysvec) > 1:
            print(f"Continuing with keys {_keys_to_text(keys)}")
            print("Use the command line option -k to provide other keys.")

        # decipher
        if args.deciphered_file is not None:
            message = f"[{_timestamp()}] Writing deciphered data {args.deciphered_file}"
            if args.keep_header:
                message += " with encryption header"
            print(message)

            compression: Optional[int] = None

            if args.cipher_archive is not None:
                with open_input(args.cipher_archive) as stream:
                    archive = Zip(stream.read())
                entry = (
                    archive[args.cipher_file]
                    if args.cipher_file is not None
                    else archive[args.cipher_index]
                )
                Zip.check_encryption(entry, Encryption.TRADITIONAL)
                compression = entry.compression

                ciphertext = archive.load(entry)
            else:
                with open_input(args.cipher_file) as stream:
                    ciphertext = stream.read()

            deciphered = decipher(
                ciphertext,
                len(ciphertext),
                0 if args.keep_header else 12,
                keys,
            )
            with open_output(args.deciphered_file) as out:
                out.write(deciphered)

            message = "Wrote deciphered data"
            if compression is not None:
                if compression == Compression.STORE:
                    message += " (not compressed)"
                else:
                    message += (
                        f" (compressed with {_compression_description(compression)} method)"
                    )
            print(message + ".")

        # decrypt
        if args.decrypted_archive is not None:
            print(f"[{_timestamp()}] Writing decrypted archive {args.decrypted_archive}")

            with open_input(args.cipher_archive) as stream:
                encrypted = Zip(stream.read())

            with ConsoleProgress() as progress:
                decrypted = encrypted.decrypt(keys, progress)

            with open_output(args.decrypted_archive) as out:
                out.write(decrypted)

        # unlock
        if args.change_password is not None:
            unlocked_archive, new_password = args.change_password

            _write(
                f"[{_timestamp()}] Writing unlocked archive {unlocked_archive} with password \"",
                new_password,
                b'"',
            )

            with open_input(args.cipher_archive) as stream:
                archive = Zip(stream.read())

            with ConsoleProgress() as progress:
                unlocked = archive.change_keys(
                    keys, Keys.from_password(new_password), progress
                )

            with open_output(unlocked_archive) as out:
                out.write(unlocked)

            print("Wrote unlocked archive.")

        if args.change_keys is not None:
            unlocked_archive, new_keys = args.change_keys

            print(
                f"[{_timestamp()}] Writing unlocked archive {unlocked_archive} "
                f"with keys {_keys_to_text(new_keys)}"
            )

            with open_input(args.cipher_archive) as stream:
                archive = Zip(stream.read())

            with ConsoleProgress() as progress:
                unlocked = archive.change_keys(keys, new_keys, progress)

            with open_output(unlocked_archive) as out:
                out.write(unlocked)

            print("Wrote unlocked archive.")

        # recover password
        if args.bruteforce or args.mask:
            print(f"[{_timestamp()}] Recovering password")

            with ConsoleProgress() as progress, _interruptible(progress):
                if args.bruteforce:
                    interval = args.length or LengthInterval()
                    passwords, restart = recover_password(
                        keys,
                        args.bruteforce,
                        interval.min_length,
                        interval.max_length,
                        args.recovery_start,
                        args.jobs,
                        args.exhaustive,
                        progress,
                    )
                else:
                    passwords, restart = recover_password_for_mask(
                        keys,
                        args.mask,
                        args.recovery_start,
                        args.jobs,
                        args.exhaustive,
                        progress,
                    )
                state = progress.state

            if state is not State.NORMAL:
                if state is State.CANCELED:
                    print("Operation interrupted by user.")
                elif state is State.EARLY_EXIT:
                    print("Found a solution. Stopping.")

                if restart:
                    print(
                        "You may resume the password recovery with the option: "
                        f"--continue-recovery {_hex_dump(restart)}"
                    )

            print(f"[{_timestamp()}] ", end="")
            if not passwords:
                print("Could not recover password")
                return 1

            print("Password")
            for password in passwords:
                _write("as bytes:" + "".join(f" {byte:02x}" for byte in password))
                _write("as text: ", password)

        return 0

    except ArgumentsError as error:
        print(error)
        print("Run 'bkcrack -h' for help.")
        return 1
    except BaseError as error:
        print(error)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
