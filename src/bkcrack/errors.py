"""Error types mirroring the C++ exception hierarchy."""

from __future__ import annotations


class BaseError(Exception):
    """Base type for all errors raised by :mod:`bkcrack`.

    The original C++ code derives ``BaseError`` from ``std::runtime_error`` and
    stores a *type* prefix printed before the description.
    """

    type_name = "Error"

    def __init__(self, description: str) -> None:
        self.description = description
        # The C++ implementation formats errors as "<type>: <description>."
        super().__init__(f"{self.type_name}: {description}.")


class ArgumentsError(BaseError):
    """Invalid command line arguments."""

    type_name = "Arguments error"


class DataError(BaseError):
    """Known plaintext and ciphertext cannot be used to carry out an attack."""

    type_name = "Data error"


class ZipError(BaseError):
    """Invalid or unsupported zip archive."""

    type_name = "Zip error"


class FileError(BaseError):
    """Input or output file cannot be opened."""

    type_name = "File error"
