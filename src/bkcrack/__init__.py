"""Python port of bkcrack, a ZipCrypto known plaintext attack tool.

This package is a faithful reimplementation of the C++ program ``bkcrack``
(version 1.8.1).  It provides the same algorithms and the same command line
interface, split into reusable Python modules:

* :mod:`bkcrack.keys` -- internal representation of the cipher state
* :mod:`bkcrack.data` -- known plaintext and ciphertext normalization
* :mod:`bkcrack.zreduction` -- generation and reduction of ``Zi[10,32)`` values
* :mod:`bkcrack.attack` -- Biham and Kocher's attack
* :mod:`bkcrack.password` -- password recovery
* :mod:`bkcrack.ziparchive` -- zip archive parsing and rewriting
* :mod:`bkcrack.cli` -- command line interface

The command line interface is also available through ``python -m bkcrack`` or
the ``bkcrack`` console script.
"""

from __future__ import annotations

__version__ = "1.8.1"
__version_date__ = "2025-10-25"

__all__ = [
    "Arguments",
    "Attack",
    "Compression",
    "Data",
    "Encryption",
    "Entry",
    "Keys",
    "Zip",
    "Zreduction",
    "attack",
    "decipher",
    "recover_password",
    "recover_password_for_mask",
    "__version__",
    "__version_date__",
]

from .arguments import Arguments
from .attack import Attack, attack
from .data import Data
from .keys import Keys
from .password import recover_password, recover_password_for_mask
from .ziparchive import Compression, Encryption, Entry, Zip, decipher
from .zreduction import Zreduction
