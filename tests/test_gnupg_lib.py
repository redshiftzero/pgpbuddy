from os import path
from contextlib import contextmanager
from unittest import TestCase
import tempfile

import gnupg
from nose.tools import nottest

from pgpbuddy.crypto import temp_pgp_dir


"""
This module contains tests that check the responses given by python-gnupg for various scenarios relevant to pgpbuddy.
Use these tests:
  - as a documentation of python-gnupg's responses
  - to make sure that a local installation of gpg and python-gnupg works with pgpbuddy

These tests require the generation of three pgp key-pairs which often is a time-consuming process.
For this reason the tests are by default NOT turned on.

To turn them on:
  1. generate key pairs
      cd test_credentials
      ./generate_keys.sh
  2. remove the @nottest annotation from the TestGnupg class

"""

credentials_dir = "test_credentials"
known_users = {"buddy": "buddy@example.com", "user1": "user1@example.com", "user2": "user2@test.nl"}

@nottest
class TestGnupg(TestCase):
    def test_decrypt_plain_text(self):
        data = b"this is a plain text message"

        result = decrypt(data, recipient="buddy")

        assert result.status == 'no data was provided'
        assert not result.ok
        assert result.data == b''
        assert not result.trust_text
        assert not result.signature_id

    #########################################################
    # test decrypting on encrypted, unsigned data
    #########################################################
    def test_decrypt__encrypted(self):
        data = b"this will be encrypted"
        encrypted = encrypt(data, recipient="buddy")

        result = decrypt(encrypted, recipient="buddy")

        assert result.status == 'decryption ok'
        assert result.ok
        assert result.data == data
        assert not result.trust_text
        assert not result.signature_id

    def test_decrypt__encrypted__wrong_recipient(self):
        data = b"this will be encrypted"
        encrypted = encrypt(data, recipient="user2")

        result = decrypt(encrypted, recipient="buddy")
        assert result.status == 'decryption failed'
        assert not result.ok
        assert result.data == b''
        assert not result.trust_text
        assert not result.signature_id

    #########################################################
    # test decrypting on encrypted, signed data
    #########################################################

    def test_decrypt___encrypted_signed__correctly(self):
        data = b"this will be encrypted and signed"
        encrypted_signed = encrypt_and_sign(data, recipient="buddy", sender="user1")

        result = decrypt(encrypted_signed, recipient="buddy", sender="user1")

        assert result.status == 'decryption ok'
        assert result.ok
        assert result.data == data
        assert result.trust_text == "TRUST_UNDEFINED"
        assert result.signature_id

    def test_decrypt__encrypted_signed__wrong_recipient(self):
        data = b"this will be encrypted and signed"
        encrypted_signed = encrypt_and_sign(data, recipient="user2", sender="user1")

        result = decrypt(encrypted_signed, recipient="buddy", sender="user1")

        assert result.status == 'decryption failed'
        assert not result.ok
        assert result.data == b''
        assert not result.trust_text
        assert not result.signature_id

    def test_decrypt__encrypted_signed__unknown_public_key(self):
        data = b"this will be encrypted and signed"
        encrypted_signed = encrypt_and_sign(data, recipient="buddy", sender="user1")
        result = decrypt(encrypted_signed, recipient="buddy", sender="user2")

        assert result.status == 'decryption ok'
        assert result.ok
        assert result.data == data
        assert not result.trust_text
        assert not result.signature_id

    def test_decrypt__encrypted_signed__recipient_unknown_public_key(self):
        data = "this will be encrypted and signed"
        encrypted_signed = encrypt_and_sign(data, recipient="buddy", sender="user1")

        result = decrypt(encrypted_signed, recipient="user2", sender="user2")

        assert result.status == 'decryption failed'
        assert not result.ok
        assert result.data == b''
        assert not result.trust_text
        assert not result.signature_id

    #########################################################
    # test decrypting on unencrypted, signed data
    #########################################################

    def test_decrypt__signed(self):
        data = b"this will be signed but not encrypted"
        signed = sign(data, sender="user1")
        result = decrypt(signed, recipient="user2", sender="user1")

        assert result.status == 'signature valid'
        assert not result.ok
        assert result.data == data + b"\n"   # random newline is added to the data
        assert result.trust_text == "TRUST_UNDEFINED"
        assert result.signature_id

    def test_decrypt__signed__unknown_public_key(self):
        data = b"this will be signed but not encrypted, also public key is unknown"
        signed = sign(data, sender="user1")

        result = decrypt(signed, recipient="buddy", sender="user2")
        assert result.status == 'no public key'
        assert not result.ok
        assert result.data == data + b"\n"   # random newline is added to the data
        assert not result.trust_text
        assert not result.signature_id

    #########################################################
    # test verifying data
    #########################################################

    def test_verify__plain_text(self):
        data = "this is a plain text message"
        result = verify(data, "user1")

        assert not result.valid
        assert result.status is None
        assert result.key_id is None

    def test_verify__signed(self):
        data = "this will be signed"
        signed = sign(data, "user1")
        result = verify(signed, "user1")

        assert result.valid
        assert result.status == 'signature valid'
        assert result.key_id
        assert result.key_id != '0'

    def test_verify__signed__public_key_unknown(self):
        data = "this will be signed"
        signed = sign(data, "user1")
        result = verify(signed, "buddy")

        assert not result.valid
        assert result.status == 'no public key'
        assert result.key_id
        assert result.key_id != '0'

    def test_verify__encrypted(self):
        data = "this will be encrypted"
        encrypted = encrypt(data, "user1")

        result = verify(encrypted, "user1")

        assert not result.valid
        assert result.status == 'unexpected data'
        assert result.key_id == '0'

    def test_verify__external_sig(self):
        data = "this will be signed"
        signed = sign(data, "user1")
        sig = b'\n'.join(signed.split(b'\n')[4:15])

        result = verify_external_sig(data, sig, "user1")

        assert result.valid
        assert result.status == 'signature valid'
        assert result.key_id
        assert result.key_id != '0'

    def test_verify__external_sig__public_key_unknown(self):
        data = "this will be signed"
        signed = sign(data, "user1")
        sig = b'\n'.join(signed.split(b'\n')[4:15])

        result = verify_external_sig(data, sig, "buddy")

        assert not result.valid
        assert result.status == 'no public key'
        assert result.key_id
        assert result.key_id != '0'

    def test_verify__external_sig__random_content(self):
        data = "this will be signed"
        sig = b'this is not actually a sig'

        result = verify_external_sig(data, sig, "buddy")
        log_verify_response(result)

        assert not result.valid
        assert result.status is None
        assert result.key_id is None

"""
Bunch of utility functions
"""


def init_gpg(user):
    gpg = gnupg.GPG(gnupghome=path.join(credentials_dir, user))
    gpg.encoding = 'utf-8'
    return gpg

@contextmanager
def merge_keyrings(user1, user2):
    gpg = init_gpg(user1)
    user1_public = gpg.export_keys(known_users[user1])
    user1_private = gpg.export_keys(known_users[user1], secret=True)
    with temp_pgp_dir(gpghome=path.join(credentials_dir, user2)) as temp_dir:
        gpg = init_gpg(temp_dir)
        gpg.import_keys(user1_public)
        gpg.import_keys(user1_private)
        yield gpg


def encrypt(text, recipient):
    gpg = init_gpg(recipient)
    return gpg.encrypt(text, recipients=[known_users[recipient]]).data


def sign(text, sender):
    gpg = init_gpg(sender)
    return gpg.sign(text).data


def verify(text, sender):
    gpg = init_gpg(sender)
    return gpg.verify(text)


def verify_external_sig(text, sig, sender):
    gpg = init_gpg(sender)
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(sig)
        tmp.flush()
        return gpg.verify_data(tmp.name, text.encode())


def encrypt_and_sign(text, recipient, sender):
    with merge_keyrings(sender, recipient) as gpg:
        return gpg.encrypt(text, recipients=[known_users[recipient]], always_trust=True, sign=sender).data


def decrypt(text, recipient, sender=None):
    # sender is not set, will not be able to do any signature verification
    if not sender:
        gpg = init_gpg(recipient)
        return gpg.decrypt(text)
    # sender was set, need to use a keyring that contains both parties keys
    else:
        with merge_keyrings(sender, recipient) as gpg:
            return gpg.decrypt(text)


def log_decrypt_response(response):
    print("status = '{}'".format(response.status))
    print("ok = {}".format(response.ok))
    print("data = {}".format(response.data))
    print("trust_text = {}".format(response.trust_text))
    print("signature_id = {}".format(response.signature_id))


def log_verify_response(response):
    print("valid = {}".format(response.valid))
    print("status = {}".format(response.status))
    print("key_id = {}".format(response.key_id))
