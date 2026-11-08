"""Tests for the command line parsing, ported from ``Arguments.test.cpp``."""

from __future__ import annotations

import pytest

from bkcrack.arguments import Arguments, LengthInterval, SIZE_MAX
from bkcrack.errors import ArgumentsError


def parse(*args: str) -> Arguments:
    return Arguments(args)


def error_message(*args: str) -> str:
    with pytest.raises(ArgumentsError) as info:
        Arguments(args)
    return info.value.description


def test_error_message():
    assert str(ArgumentsError("description")) == "Arguments error: description."


def test_attack_with_files():
    args = parse("-c", "cipher", "-p", "plain")

    assert args.cipher_file == "cipher"
    assert args.plain_file == "plain"
    assert args.plain_file_prefix == 1024 * 1024
    assert args.offset == 0
    assert args.extra_plaintext == {}
    assert args.ignore_check_byte is False
    assert args.attack_start == 0
    assert args.jobs >= 1
    assert args.exhaustive is False


def test_attack_with_entry_names():
    args = parse("-C", "encrypted.zip", "-c", "cipher", "-P", "plain.zip", "-p", "plain")

    assert args.cipher_archive == "encrypted.zip"
    assert args.cipher_file == "cipher"
    assert args.plain_archive == "plain.zip"
    assert args.plain_file == "plain"


def test_attack_with_entry_indices():
    args = parse("-C", "encrypted.zip", "--cipher-index", "1", "-P", "plain.zip", "--plain-index", "2")

    assert args.cipher_archive == "encrypted.zip"
    assert args.cipher_index == 1
    assert args.plain_archive == "plain.zip"
    assert args.plain_index == 2


def test_truncate_plaintext():
    assert parse("-c", "cipher", "-p", "plain", "-t", "42").plain_file_prefix == 42


def test_plaintext_offset():
    assert parse("-c", "cipher", "-p", "plain", "-o", "123").offset == 123


def test_extra_plaintext():
    args = parse("-c", "cipher", "-p", "plain", "-x", "10", "012345", "-x", "20", "6789ab")
    assert args.extra_plaintext == {10: 0x01, 11: 0x23, 12: 0x45, 20: 0x67, 21: 0x89, 22: 0xAB}


def test_ignore_check_byte():
    assert parse("-c", "cipher", "-p", "plain", "--ignore-check-byte").ignore_check_byte is True


def test_attack_checkpoint():
    assert parse("-c", "cipher", "-p", "plain", "--continue-attack", "456").attack_start == 456


def test_attack_job_count():
    assert parse("-c", "cipher", "-p", "plain", "-j", "7").jobs == 7


def test_exhaustive():
    assert parse("-c", "cipher", "-p", "plain", "-e").exhaustive is True


def test_password():
    assert parse("--password", "password").password == b"password"


def test_decipher():
    args = parse("-k", "ab", "cd", "ef", "-c", "cipher", "-d", "output")

    assert args.keys is not None
    assert (args.keys.x, args.keys.y, args.keys.z) == (0xAB, 0xCD, 0xEF)
    assert args.cipher_file == "cipher"
    assert args.deciphered_file == "output"
    assert args.keep_header is False


def test_decipher_with_header():
    args = parse("-k", "ab", "cd", "ef", "-c", "cipher", "-d", "output", "--keep-header")
    assert args.keep_header is True


def test_decrypt():
    args = parse("-k", "ab", "cd", "ef", "-C", "encrypted.zip", "-D", "output.zip")

    assert args.keys is not None
    assert args.cipher_archive == "encrypted.zip"
    assert args.decrypted_archive == "output.zip"


def test_change_password():
    args = parse("-k", "ab", "cd", "ef", "-C", "encrypted.zip", "-U", "output.zip", "password")

    assert args.change_password == ("output.zip", b"password")


def test_change_keys():
    args = parse("-k", "ab", "cd", "ef", "-C", "encrypted.zip", "--change-keys", "output.zip", "123", "456", "789")

    assert args.change_keys is not None
    assert args.change_keys[0] == "output.zip"
    assert (args.change_keys[1].x, args.change_keys[1].y, args.change_keys[1].z) == (0x123, 0x456, 0x789)


def test_bruteforce():
    args = parse("-k", "ab", "cd", "ef", "-b", "?d")

    assert args.bruteforce == list(range(ord("0"), ord("9") + 1))
    assert args.length is None


@pytest.mark.parametrize(
    "value, min_length, max_length",
    [
        ("5..15", 5, 15),
        ("..15", 0, 15),
        ("5..", 5, SIZE_MAX),
        ("8", 8, 8),
    ],
)
def test_bruteforce_with_length_range(value, min_length, max_length):
    args = parse("-k", "ab", "cd", "ef", "-b", "?d", "-l", value)

    assert args.length is not None
    assert args.length.min_length == min_length
    assert args.length.max_length == max_length


@pytest.mark.parametrize(
    "value, min_length, max_length",
    [
        ("5..15", 5, 15),
        ("..15", 0, 15),
        ("5..", 5, SIZE_MAX),
        ("8", 0, 8),
    ],
)
def test_recover_password_with_length_range(value, min_length, max_length):
    args = parse("-k", "ab", "cd", "ef", "-r", value, "?d")

    assert args.length is not None
    assert args.length.min_length == min_length
    assert args.length.max_length == max_length


def test_mask():
    args = parse("-k", "ab", "cd", "ef", "-m", "?u?l?d??0")

    upper = list(range(ord("A"), ord("Z") + 1))
    lower = list(range(ord("a"), ord("z") + 1))
    digits = list(range(ord("0"), ord("9") + 1))

    assert args.mask == [upper, lower, digits, [ord("?")], [ord("0")]]


def test_mask_with_custom_charsets():
    args = parse("-k", "ab", "cd", "ef", "-m", "?x?y", "-s", "x", "123", "-s", "y", "456?x")

    assert args.mask == [
        [ord("1"), ord("2"), ord("3")],
        [ord("1"), ord("2"), ord("3"), ord("4"), ord("5"), ord("6")],
    ]


def test_password_recovery_checkpoint():
    args = parse("-k", "ab", "cd", "ef", "-b", "?d", "--continue-recovery", "343536")
    assert args.recovery_start == b"456"


def test_list():
    assert parse("-L", "archive.zip").info_archive == "archive.zip"


def test_version():
    assert parse("--version").version is True


@pytest.mark.parametrize("option", ["-h", "--help"])
def test_help(option):
    assert parse(option).help is True


def test_no_arguments():
    assert error_message() == "-c or --cipher-index parameter is missing"


def test_invalid_number():
    assert error_message("-c", "cipher", "-p", "plain", "-o", "text") == 'expected an integer, got "text"'


def test_out_of_range_number():
    assert (
        error_message("-c", "cipher", "-p", "plain", "-o", "5000000000")
        == "integer value 5000000000 is out of range"
    )


def test_missing_action_with_keys():
    assert "parameter is missing (required by -k)" in error_message("-k", "ab", "cd", "ef")


def test_incompatible_ciphertext_entry_specifications():
    assert (
        error_message("-c", "cipher", "--cipher-index", "1", "-p", "plain")
        == "-c and --cipher-index cannot be used at the same time"
    )


def test_incompatible_plaintext_entry_specifications():
    assert (
        error_message("-c", "cipher", "-p", "plain", "--plain-index", "1")
        == "-p and --plain-index cannot be used at the same time"
    )


def test_missing_ciphertext():
    assert (
        error_message("-p", "plain") == "-c or --cipher-index parameter is missing"
    )


def test_missing_plaintext():
    assert error_message("-c", "cipher") == "-p, --plain-index or -x parameter is missing"


def test_missing_plaintext_entry():
    assert (
        error_message("-c", "cipher", "-P", "plain.zip", "-x", "0", "abcd")
        == "-p or --plain-index parameter is missing (required by -P)"
    )


def test_missing_archive_to_load_ciphertext_entry():
    assert (
        error_message("--cipher-index", "1", "-p", "plain")
        == "-C parameter is missing (required by --cipher-index)"
    )


def test_missing_archive_to_load_plaintext_entry():
    assert (
        error_message("-c", "cipher", "--plain-index", "1")
        == "-P parameter is missing (required by --plain-index)"
    )


def test_invalid_offset():
    assert (
        error_message("-c", "cipher", "-p", "plain", "-o", "-13")
        == "plaintext offset -13 is too small (minimum is -12)"
    )


def test_invalid_extra_plaintext_offset():
    assert (
        error_message("-c", "cipher", "-x", "-13", "abcd")
        == "extra plaintext offset -13 is too small (minimum is -12)"
    )


def test_invalid_hex_string_length():
    assert error_message("-c", "cipher", "-x", "0", "123") == "expected an even-length string, got 123"


def test_invalid_hex_string_characters():
    assert error_message("-c", "cipher", "-x", "0", "ghij") == "expected data in hexadecimal, got ghij"


def test_invalid_key_component_length():
    assert (
        error_message("-k", "123456789", "222", "333", "-c", "cipher", "-d", "output")
        == "expected a string of length 8 or less, got 123456789"
    )


def test_invalid_key_component_character():
    assert (
        error_message("-k", "ggg", "222", "333", "-c", "cipher", "-d", "output")
        == "expected X in hexadecimal, got ggg"
    )


def test_missing_ciphertext_to_decipher():
    assert (
        error_message("-k", "ab", "cd", "ef", "-d", "output")
        == "-c or --cipher-index parameter is missing (required by -d)"
    )


def test_missing_archive_to_decrypt():
    assert error_message("-k", "ab", "cd", "ef", "-D", "output.zip") == "-C parameter is missing (required by -D)"


def test_missing_archive_to_change_password():
    assert (
        error_message("-k", "ab", "cd", "ef", "-U", "output.zip", "password")
        == "-C parameter is missing (required by -U)"
    )


def test_missing_archive_to_change_keys():
    assert (
        error_message("-k", "ab", "cd", "ef", "--change-keys", "output.zip", "123", "456", "789")
        == "-C parameter is missing (required by --change-keys)"
    )


def test_missing_charset():
    assert (
        error_message("-k", "ab", "cd", "ef", "-c", "cipher", "-d", "output", "-l", "12")
        == "--bruteforce parameter is missing (required by --length)"
    )


def test_incompatible_password_recovery_methods():
    assert (
        error_message("-k", "ab", "cd", "ef", "-b", "?a", "-m", "?a?a?a?a")
        == "--bruteforce and --mask cannot be used at the same time"
    )


def test_unknown_charset():
    assert error_message("-k", "ab", "cd", "ef", "-b", "?x") == "unknown charset ?x"


def test_circular_charset_reference():
    assert (
        error_message("-k", "ab", "cd", "ef", "-b", "?x", "-s", "x", "?y", "-s", "y", "?x")
        == "circular reference resolving charset ?x"
    )


def test_charset_identifier_length():
    assert (
        error_message("-k", "ab", "cd", "ef", "-b", "?d", "-s", "xy", "abc")
        == 'charset identifier must be a single character, got "xy"'
    )


def test_charset_redefinition():
    assert (
        error_message("-k", "ab", "cd", "ef", "-b", "?d", "-s", "d", "abc")
        == "charset ?d is already defined, it cannot be redefined"
    )


def test_empty_charset():
    assert error_message("-k", "ab", "cd", "ef", "-b", "") == "charset for bruteforce password recovery is empty"


def test_unknown_option():
    assert error_message("--bogus") == "unknown option --bogus"


def test_length_interval_intersection():
    interval = LengthInterval(1, 10) & LengthInterval(5, 20)
    assert (interval.min_length, interval.max_length) == (5, 10)


def test_hexadecimal_numbers():
    args = parse("-c", "cipher", "-p", "plain", "-o", "0x10", "-t", "010")
    assert args.offset == 16
    assert args.plain_file_prefix == 8
