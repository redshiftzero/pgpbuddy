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
    def test_plain_attachment(self, gpg):
        attachments = [("blabla", None)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)

        assert_list_equal(attachments, remaining_attachments)
        assert not gpg.import_keys.called

    @patch('gnupg.GPG', import_keys=mock_import_keys(True))
    def test_key_attachment(self, gpg):
        key = self._mock_key("PRETEND THIS IS A KEY")
        attachments = [(key, None)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)

        expected = []
        assert_list_equal(expected, remaining_attachments)
        gpg.import_keys.assert_called_once_with(self.__format_key(key))

    @patch('gnupg.GPG', import_keys=mock_import_keys(False))
    def test_key_attachment_import_fails(self, gpg):
        key = self._mock_key("PRETEND THIS IS A KEY")
        attachments = [(key, None)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)

        expected = attachments
        assert_list_equal(expected, remaining_attachments)
        gpg.import_keys.assert_called_once_with(self.__format_key(key))

    @patch('gnupg.GPG')
    def test_binary_attachment(self, gpg):
        attachments = [(self._mock_key("This will be binary so not considered a key").encode(), None)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)

        expected = attachments
        assert_list_equal(expected, remaining_attachments)
        assert not gpg.import_keys.called

    @patch('gnupg.GPG', import_keys=mock_import_keys([False, True, True]))
    def test_mixture_of_everything(self, gpg):
        key1 = self._mock_key("Failing key")
        key2 = self._mock_key("Succeeding key")
        key3 = self._mock_key("Another succeeding key")
        attachments = [("blabla", None), (key1, None), (b"binary", None), (key2, None), ("ladida", None),  (key3, None)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)

        expected = [attachments[0], attachments[1], attachments[2], attachments[4]]
        assert_list_equal(expected, remaining_attachments)
        gpg.import_keys.assert_any_call(self.__format_key(key1))
        gpg.import_keys.assert_any_call(self.__format_key(key2))
        gpg.import_keys.assert_any_call(self.__format_key(key3))

    @patch('gnupg.GPG')
    def test_preserve_encryption_status(self, gpg):
        attachments = [("bla", Encryption.missing), ("blu", Encryption.correct), ("ble", Encryption.incorrect)]

        remaining_attachments = import_public_keys_from_attachments(gpg, attachments)

        expected = attachments
        assert_list_equal(expected, remaining_attachments)
        assert not gpg.import_keys.called

    @staticmethod
    def __format_key(key):
        return key.strip().split("\n")


class TestImportFromKeyServer():

    server = 'pgp.mit.edu'

    @patch('gnupg.GPG', search_keys=mock_search_keys([]), recv_keys=mock_recv_keys())
    def test_no_key_found(self, gpg):
        sender = "sender@plain.txt"
        import_public_keys_from_server(gpg, sender)

        gpg.search_keys.assert_called_once_with(sender, self.server)
        assert not gpg.recv_keys.called

    @patch('gnupg.GPG', search_keys=mock_search_keys(["key1"]), recv_keys=mock_recv_keys())
    def test_one_key_found(self, gpg):
        sender = "sender@plain.txt"
        import_public_keys_from_server(gpg, sender)

        gpg.search_keys.assert_called_once_with(sender, self.server)
        gpg.recv_keys.assert_called_once_with(self.server, "key1")

    @patch('gnupg.GPG', search_keys=mock_search_keys(["key1", "key2"]), recv_keys=mock_recv_keys())
    def test_two_keys_found(self, gpg):
        sender = "sender@plain.txt"
        import_public_keys_from_server(gpg, sender)

        gpg.search_keys.assert_called_once_with(sender, self.server)
        gpg.recv_keys.assert_any_call(self.server, "key1")
        gpg.recv_keys.assert_any_call(self.server, "key2")
