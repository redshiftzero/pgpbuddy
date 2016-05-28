from os import path

from unittest.mock import patch
from nose_parameterized import parameterized

from tests.mock_gpg import *
from pgpbuddy.fetch import parse_message
from pgpbuddy.buddy import handle_message


mailclients = ["thunderbird_enigmail"]


@parameterized(mailclients)
@patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.missing, Signature.correct), sign=mock_sign(success=True))
def test_inline_signed(client, gpg):
    message = message_from_file(client, "inline_signed.txt")
    message = parse_message(message)
    _, encryption_status, signature_status, _ = handle_message(gpg, message)
    assert encryption_status == Encryption.missing
    assert signature_status == Signature.correct


@parameterized(mailclients)
@patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.correct, Signature.missing), encrypt=mock_encrypt(success=True))
def test_inline_encrypted(client, gpg):
    message = message_from_file(client, "inline_encrypted.txt")
    message = parse_message(message)
    _, encryption_status, signature_status, _ = handle_message(gpg, message)
    assert encryption_status == Encryption.correct
    assert signature_status == Signature.missing


@parameterized(mailclients)
@patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.missing, Signature.correct), sign=mock_sign(success=True))
def test_multipart_signed(client, gpg):
    message = message_from_file(client, "multipart_signed.txt")
    message = parse_message(message)
    _, encryption_status, signature_status, _ = handle_message(gpg, message)
    assert encryption_status == Encryption.missing
    assert signature_status == Signature.correct


@parameterized(mailclients)
@patch('gnupg.GPG', encrypt=mock_encrypt(success=True))
def test_multipart_encrypted(client, gpg):
    message = message_from_file(client, "multipart_encrypted.txt")
    decrypted_body = b"\n".join(message_from_file(client, "multipart_encrypted_body.txt"))

    gpg.decrypt = mock_decrypt(Encryption.correct, Signature.missing, decrypted_body)

    message = parse_message(message)
    _, encryption_status, signature_status, _ = handle_message(gpg, message)
    assert encryption_status == Encryption.correct
    assert signature_status == Signature.missing


def message_from_file(client, filename):
    filename = ["tests", "samples", client, filename]
    filename = path.join(*filename)
    with open(filename) as message:
        return [line.replace("\n", "").encode() for line in message]