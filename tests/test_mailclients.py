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
    result = handle_message(gpg, message)
    assert "PGP email successfully signed!" in result["Subject"]    # todo assert against Signature/Encryption status


def message_from_file(client, filename):
    filename = path.join(path.join("samples", client), filename)
    with open(filename) as message:
        return [line.replace("\n", "").encode() for line in message]