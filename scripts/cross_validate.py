#!/usr/bin/env python3
"""Cross-validate this Python port against the official bkcrack binary.

The script runs both implementations on the same inputs and compares their
output (stdout and produced files).  Timestamps and progress lines are
normalized before comparing because they depend on the machine and on timing.

Usage
-----
    python scripts/cross_validate.py
    python scripts/cross_validate.py --binary /path/to/bkcrack --attack

The official binary is looked up in ``_refbin/`` first, then in the ``PATH``.
Exit code is 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "tests" / "data"
EXAMPLE_ARCHIVE = PROJECT_DIR / "reference" / "example" / "secrets.zip"

#: Keys of the example archive, as documented in the official tutorial.
EXAMPLE_KEYS = ["c4490e28", "b414a23d", "91404b31"]
EXAMPLE_PLAINTEXT = b'<?xml version="1.0" '

TIMESTAMP_RE = re.compile(r"\[\d{2}:\d{2}:\d{2}\]")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
PROGRESS_RE = re.compile(r"^\s*\d+(?:\.\d+)? % \(\d+ / \d+\)\s*$")
ATTACK_RESUME_RE = re.compile(r"^You may resume the attack with the option: --continue-attack \d+$")


def normalize(text: str, drop_attack_resume: bool = False) -> List[str]:
    """Normalize the output of both implementations for comparison.

    Timestamps, terminal escape sequences and progress lines are dropped
    because they depend on the machine, on the terminal and on timing.
    """
    text = text.replace("\r", "\n")
    text = TIMESTAMP_RE.sub("[TIME]", text)
    text = ANSI_RE.sub("", text)

    lines = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if PROGRESS_RE.match(line):
            continue
        if drop_attack_resume and ATTACK_RESUME_RE.match(line):
            continue
        lines.append(line.rstrip())
    return lines


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mask_path(text: str, path: str) -> str:
    """Replace occurrences of *path* with a placeholder."""
    return text.replace(path, "{output}")


class CrossValidator:
    def __init__(self, python_cmd: Sequence[str], binary: Optional[Path], verbose: bool) -> None:
        self.python_cmd = list(python_cmd)
        self.binary = binary
        self.verbose = verbose
        self.workdir = Path(tempfile.mkdtemp(prefix="bkcrack-crossval-"))
        self.results: List[Tuple[str, bool, str]] = []
        self.durations = {"official": 0.0, "python": 0.0}

    # -- running -----------------------------------------------------------

    def run_python(self, args: Sequence[str], cwd: Path) -> subprocess.CompletedProcess:
        start = time.monotonic()
        result = subprocess.run(
            [*self.python_cmd, "-m", "bkcrack", *args],
            cwd=str(cwd),
            capture_output=True,
        )
        self.durations["python"] = time.monotonic() - start
        return result

    def run_reference(self, args: Sequence[str], cwd: Path) -> subprocess.CompletedProcess:
        assert self.binary is not None
        start = time.monotonic()
        result = subprocess.run(
            [str(self.binary), *args],
            cwd=str(cwd),
            capture_output=True,
        )
        self.durations["official"] = time.monotonic() - start
        return result

    # -- checks ------------------------------------------------------------

    def check_output(
        self,
        name: str,
        args: Sequence[str],
        drop_attack_resume: bool = False,
        cwd: Optional[Path] = None,
    ) -> None:
        cwd = cwd or self.workdir
        reference = self.run_reference(args, cwd)
        port = self.run_python(args, cwd)

        reference_lines = normalize(reference.stdout.decode("utf-8", "replace"), drop_attack_resume)
        port_lines = normalize(port.stdout.decode("utf-8", "replace"), drop_attack_resume)

        problems = []
        if reference.returncode != port.returncode:
            problems.append(f"exit code {reference.returncode} != {port.returncode}")
        if reference_lines != port_lines:
            problems.append(
                "output differs:\n  official: {}\n  python:   {}".format(
                    reference_lines[:10], port_lines[:10]
                )
            )

        self._record(name, problems)

    def check_files(
        self,
        name: str,
        prepare: "callable",
        args_template: Sequence[str],
    ) -> None:
        """Run both implementations with their own output file and compare the files."""
        reference_out = self.workdir / f"{name}-official.out"
        port_out = self.workdir / f"{name}-python.out"

        prepare(self.workdir)

        reference = self.run_reference(
            [str(reference_out) if arg == "{output}" else arg for arg in args_template], self.workdir
        )
        port = self.run_python(
            [str(port_out) if arg == "{output}" else arg for arg in args_template], self.workdir
        )

        problems = []
        if reference.returncode != port.returncode:
            problems.append(f"exit code {reference.returncode} != {port.returncode}")
        if not reference_out.is_file() or not port_out.is_file():
            problems.append("output file missing")
        elif reference_out.read_bytes() != port_out.read_bytes():
            problems.append(
                f"output differs ({reference_out.stat().st_size} vs {port_out.stat().st_size} bytes)"
            )
        else:
            # the output file name appears in the messages, so mask it
            reference_lines = normalize(
                _mask_path(reference.stdout.decode("utf-8", "replace"), str(reference_out))
            )
            port_lines = normalize(
                _mask_path(port.stdout.decode("utf-8", "replace"), str(port_out))
            )
            if reference_lines != port_lines:
                problems.append(
                    "messages differ:\n  official: {}\n  python:   {}".format(
                        reference_lines[:10], port_lines[:10]
                    )
                )

        self._record(name, problems)

    def _record(self, name: str, problems: List[str]) -> None:
        self.results.append((name, not problems, "; ".join(problems)))
        status = "ok" if not problems else "FAIL"
        print(f"[{status}] {name}")
        for problem in problems:
            print(f"       {problem}")

    # -- preparation helpers ----------------------------------------------

    def prepare_example_plaintext(self, directory: Path) -> Path:
        path = directory / "example-plain.txt"
        path.write_bytes(EXAMPLE_PLAINTEXT)
        return path

    # -- test plan ---------------------------------------------------------

    def run(self, with_attack: bool) -> bool:
        print(f"official binary: {self.binary}")
        print(f"python command:  {' '.join(self.python_cmd)}")
        print(f"work directory:  {self.workdir}")
        print()

        self.check_output("version", ["--version"])
        self.check_output("help", ["-h"])

        for archive in sorted(DATA_DIR.glob("*.zip")):
            self.check_output(f"list {archive.name}", ["-L", str(archive)])
        if EXAMPLE_ARCHIVE.is_file():
            self.check_output("list example archive", ["-L", str(EXAMPLE_ARCHIVE)])

        for password in ["password", "a", "", "pässwörd"]:
            self.check_output(f"password {password!r}", ["--password", password])

        # error handling
        self.check_output("unknown option", ["--bogus"])
        self.check_output("missing argument", ["-c"])
        self.check_output("invalid number", ["-c", "cipher", "-p", "plain", "-o", "text"])
        self.check_output("missing ciphertext", ["-p", "plain"])
        self.check_output("unknown file", ["-c", "no-such-file", "-p", "no-such-file"])
        self.check_output("invalid offset", ["-c", "cipher", "-p", "plain", "-o", "-13"])
        self.check_output("unknown charset", ["-k", "1", "2", "3", "-b", "?x"])

        # decipher entries of the test archive
        self.check_files(
            "decipher store.txt",
            lambda dir: None,
            [
                "-C", str(DATA_DIR / "zipcrypto.zip"),
                "-c", "store.txt",
                "-k", "ea9b4e4d", "ba789085", "5ff8707d",
                "-d", "{output}",
            ],
        )
        self.check_files(
            "decipher deflate.txt",
            lambda dir: None,
            [
                "-C", str(DATA_DIR / "zipcrypto.zip"),
                "-c", "deflate.txt",
                "-k", "ea9b4e4d", "ba789085", "5ff8707d",
                "-d", "{output}",
            ],
        )
        self.check_files(
            "decipher with header",
            lambda dir: None,
            [
                "-C", str(DATA_DIR / "zipcrypto.zip"),
                "-c", "store.txt",
                "-k", "ea9b4e4d", "ba789085", "5ff8707d",
                "-d", "{output}",
                "--keep-header",
            ],
        )

        if EXAMPLE_ARCHIVE.is_file():
            for entry in ["advice.jpg", "spiral.svg"]:
                self.check_files(
                    f"decipher {entry}",
                    lambda dir: None,
                    [
                        "-C", str(EXAMPLE_ARCHIVE),
                        "-c", entry,
                        "-k", *EXAMPLE_KEYS,
                        "-d", "{output}",
                    ],
                )

        # rewrite whole archives
        for archive in ["zipcrypto.zip", "zip64-zipcrypto.zip", "aes256.zip"]:
            self.check_files(
                f"decrypt {archive}",
                lambda dir: None,
                [
                    "-C", str(DATA_DIR / archive),
                    "-k", "ea9b4e4d", "ba789085", "5ff8707d",
                    "-D", "{output}",
                ],
            )

        self.check_files(
            "change password",
            lambda dir: None,
            [
                "-C", str(DATA_DIR / "zipcrypto.zip"),
                "-k", "ea9b4e4d", "ba789085", "5ff8707d",
                "-U", "{output}", "new_password",
            ],
        )
        self.check_files(
            "change keys",
            lambda dir: None,
            [
                "-C", str(DATA_DIR / "zipcrypto.zip"),
                "-k", "ea9b4e4d", "ba789085", "5ff8707d",
                "--change-keys", "{output}", "11223344", "55667788", "99aabbcc",
            ],
        )

        # password recovery
        self.check_output(
            "recover 4 bytes password",
            ["-k", "1b226dfe", "c089e0a3", "6af00ee6", "-r", "..4", "?b"],
        )
        self.check_output(
            "recover 8 characters password",
            ["-k", "9bcb20c6", "10a97ca5", "103c0614", "-b", "?p", "-l", "8"],
        )
        self.check_output(
            "recover password out of charset",
            ["-k", "f1f9ab49", "8574a6fd", "cb99758d", "-b", "?d", "-l", "6"],
        )
        self.check_output(
            "recover password with mask",
            ["-k", "5e07e483", "0c4900a4", "4e586ac1", "-m", "?u?l?d?s."],
        )
        self.check_output(
            "recover password with constant mask",
            ["-k", "c80f5189", "ce16bd43", "38247eb5", "-m", "Lorem ipsum dolor sit amet"],
        )
        self.check_output(
            "recover password with custom charset",
            ["-k", "5e07e483", "0c4900a4", "4e586ac1", "-m", "?u?l?d?s.", "-s", "h", "?dabcdef"],
        )

        if with_attack and EXAMPLE_ARCHIVE.is_file():
            plaintext = self.prepare_example_plaintext(self.workdir)
            print("\nrunning the full attack on the example archive (this takes a while)...")
            self.check_output(
                "attack on example archive",
                ["-C", str(EXAMPLE_ARCHIVE), "-c", "spiral.svg", "-p", str(plaintext)],
                drop_attack_resume=True,
            )
            print(
                "       official {:.1f} s, python {:.1f} s".format(
                    self.durations["official"], self.durations["python"]
                )
            )

        return self.report()

    def report(self) -> bool:
        failures = [name for name, ok, _ in self.results if not ok]
        print()
        print(f"{len(self.results) - len(failures)}/{len(self.results)} checks passed")
        if failures:
            print("failed checks:")
            for name in failures:
                print(f"  - {name}")
            return False
        print("all checks passed")
        return True

    def cleanup(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)


def find_binary(explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        path = Path(explicit)
        return path if path.is_file() else None

    candidates = sorted((PROJECT_DIR / "_refbin").glob("*/bkcrack.exe")) + sorted(
        (PROJECT_DIR / "_refbin").glob("*/bkcrack")
    )
    if candidates:
        return candidates[0]

    found = shutil.which("bkcrack")
    return Path(found) if found else None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", help="path to the official bkcrack executable")
    parser.add_argument(
        "--attack",
        action="store_true",
        help="also run the full attack on the example archive (takes several minutes)",
    )
    parser.add_argument("--python", default=sys.executable, help="Python interpreter to use")
    parser.add_argument("--verbose", action="store_true")
    options = parser.parse_args(argv)

    binary = find_binary(options.binary)
    if binary is None:
        print("could not find the official bkcrack binary; use --binary or set BKCRACK_OFFICIAL")
        return 2

    if not EXAMPLE_ARCHIVE.is_file():
        print(f"warning: {EXAMPLE_ARCHIVE} is missing, example checks are skipped")

    validator = CrossValidator([options.python], binary, options.verbose)
    try:
        success = validator.run(with_attack=options.attack)
    finally:
        if not options.verbose:
            validator.cleanup()
        else:
            print(f"work directory kept: {validator.workdir}")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
