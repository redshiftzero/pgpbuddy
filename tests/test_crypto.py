from unittest.mock import  patch
from unittest import TestCase

from pgpbuddy.crypto import check_encryption_and_signature, Encryption, Signature
from tests.mock_gpg import mock_decrypt, mock_decrypt_unexpected_output


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