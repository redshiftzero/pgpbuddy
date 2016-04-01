from unittest.mock import  patch
from unittest import TestCase

from nose.tools import assert_list_equal

from pgpbuddy.crypto import *
from tests.mock_gpg import *

class TestCheckEncryptionAndSignature(TestCase):

    @patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.missing, Signature.missing))
    def test_plain(self, gpg):
        encryption_status, signature_status, reason = check_encryption_and_signature(gpg, "blabla")
        assert encryption_status == Encryption.missing
        assert signature_status == Signature.missing
        assert not reason

    @patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.missing, Signature.incorrect))
    def test_not_encrypted_incorrect_signature(self, gpg):
        encryption_status, signature_status, reason = check_encryption_and_signature(gpg, "blabla")
        assert encryption_status == Encryption.missing
        assert signature_status == Signature.incorrect
        assert reason

    @patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.missing, Signature.correct))
    def test_not_encrypted_correct_signature(self, gpg):
        encryption_status, signature_status, reason = check_encryption_and_signature(gpg, "blabla")
        assert encryption_status == Encryption.missing
        assert signature_status == Signature.correct
        assert not reason

    @patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.correct, Signature.missing))
    def test_correct_encrypted_no_sig(self, gpg):
        encryption_status, signature_status, reason = check_encryption_and_signature(gpg, "blabla")
        assert encryption_status == Encryption.correct
        assert signature_status == Signature.missing
        assert not reason

    @patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.correct, Signature.incorrect))
    def test_correct_encrypted_incorrect_sig(self, gpg):
        encryption_status, signature_status, reason = check_encryption_and_signature(gpg, "blabla")
        assert encryption_status == Encryption.correct
        assert signature_status == Signature.incorrect
        assert reason

    @patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.correct, Signature.correct))
    def test_correct_encrypted_correct_sig(self, gpg):
        encryption_status, signature_status, reason = check_encryption_and_signature(gpg, "blabla")
        assert encryption_status == Encryption.correct
        assert signature_status == Signature.correct
        assert not reason

    @patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.incorrect, Signature.correct))
    def test_incorrect_encrypted_sig_correct(self, gpg):
        encryption_status, signature_status, reason = check_encryption_and_signature(gpg, "blabla")
        assert encryption_status == Encryption.incorrect
        assert signature_status == Signature.missing   # with incorrect encryption can not check the sig
        assert reason

    @patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.incorrect, Signature.missing))
    def test_incorrect_encrypted_sig_missing(self, gpg):
        encryption_status, signature_status, reason = check_encryption_and_signature(gpg, "blabla")
        assert encryption_status == Encryption.incorrect
        assert signature_status == Signature.missing   # with incorrect encryption can not check the sig
        assert reason

    @patch('gnupg.GPG', decrypt=mock_decrypt(Encryption.incorrect, Signature.incorrect))
    def test_incorrect_encrypted_sig_incorrect(self, gpg):
        encryption_status, signature_status, reason = check_encryption_and_signature(gpg, "blabla")
        assert encryption_status == Encryption.incorrect
        assert signature_status == Signature.missing   # with incorrect encryption can not check the sig
        assert reason

    @patch('gnupg.GPG', decrypt=mock_decrypt_unexpected_output())
    def test_fallback(self, gpg):
        encryption_status, signature_status, reason = check_encryption_and_signature(gpg, "blabla")
        assert encryption_status == Encryption.incorrect
        assert signature_status == Signature.incorrect
        assert reason


class TestImportKeysFromAttachments(TestCase):

    def _mock_key(self, content):
        return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n{}\n-----END PGP PUBLIC KEY BLOCK-----\n".format(content)

    @patch('gnupg.GPG')
    def test_no_attachments(self, gpg):
        attachments = []

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)
        assert remaining_attachments == []
        assert not gpg.import_keys.called

    @patch('gnupg.GPG')
    def test_one_plain_attachment(self, gpg):
        attachments = [("blabla", None)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)
        assert_list_equal(attachments, remaining_attachments)
        assert not gpg.import_keys.called

    @patch('gnupg.GPG')
    def test_two_plain_attachments(self, gpg):
        attachments = [("blabla", None), ("blublu", None)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)
        assert_list_equal(attachments, remaining_attachments)
        assert not gpg.import_keys.called

    @patch('gnupg.GPG', import_keys=mock_import_keys(success=True))
    def test_one_key_attachment(self, gpg):
        key = self._mock_key("PRETEND THIS IS A KEY")
        attachments = [(key, None)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)

        expected = []
        assert_list_equal(expected, remaining_attachments)

    @patch('gnupg.GPG', import_keys=mock_import_keys(success=True))
    def test_one_key_attachment_one_other(self, gpg):
        key = self._mock_key("PRETEND THIS IS A KEY")
        attachments = [(key, None), ("blablu", None)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)

        expected = [attachments[1]]
        assert_list_equal(expected, remaining_attachments)

    @patch('gnupg.GPG', import_keys=mock_import_keys(success=True))
    def test_one_key_attachment_one_other_different_order(self, gpg):
        key = self._mock_key("PRETEND THIS IS A KEY")
        attachments = [("blablu", None), (key, None)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)

        expected = [attachments[0]]
        assert_list_equal(expected, remaining_attachments)