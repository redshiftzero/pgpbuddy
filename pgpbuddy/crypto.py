from contextlib import contextmanager
import shutil
import logging
import tempfile
from os import path
from enum import Enum

import gnupg


log = logging.getLogger(__name__)

PublicKey = Enum('PublicKey', 'available not_available')
Signature = Enum('Signature', 'correct incorrect missing')
Encryption = Enum('Encryption', 'correct incorrect missing')
ResponseEncryption = Enum('ResponseEncryption', 'plain sign encrypt_and_sign encrypt_fails_but_sign')


def import_public_keys_from_attachments(gpg, attachments):
    def try_import(data):
        # it is a binary attachment, can not contain the PUBLIC KEY block
        if isinstance(data, bytes):
            return False

        # check if the usual markers for PUBLIC KEY block are there
        data = data.strip().split("\n")
        if data[0] != "-----BEGIN PGP PUBLIC KEY BLOCK-----" or data[-1] != "-----END PGP PUBLIC KEY BLOCK-----":
            return False

        # looks like a PUBLIC KEY block, try to import it into keyring and report on results
        result = gpg.import_keys(data)
        if result.results[0]['ok'] == '1':
            return True
        else:
            return False

    imported = [i for i, (attach, _) in enumerate(attachments) if try_import(attach)]
    remaining_attachments = [attach for i, attach in enumerate(attachments) if i not in imported]
    return remaining_attachments


def import_public_keys_from_server(gpg, sender):
    keys = gpg.search_keys(sender, "pgp.mit.edu")
    for key in keys:
        gpg.recv_keys("pgp.mit.edu", key["keyid"])


def decrypt_attachment(gpg, data):
    result = gpg.decrypt(data)
    if result.status == 'decryption ok':
        return result.data.decode('UTF-8', "replace"), Encryption.correct
    elif result.status == 'decryption failed':
        return data, Encryption.incorrect
    else:
        # todo signed attachments are not checked here, consider merging method with check_encryption_and_signature
        # probably will need to run for attachments twice:
        #  1. decrypt attachments to be able to import attached, encrypted public keys
        #  2. check attachment signature
        return data, Encryption.missing


def check_public_key_available(gpg, sender):
    result = gpg.encrypt("blabla", recipients=sender, always_trust=True)
    if result.ok:
        return PublicKey.available
    else:
        return PublicKey.not_available


def contains_signature(attachment):
    # it is a binary attachment, can not contain the PUBLIC KEY block
    if type(attachment) == bytes:
        return False

    attachment = attachment.strip().split("\n")
    if attachment[0] == "-----BEGIN PGP SIGNATURE-----" and attachment[-1] == "-----END PGP SIGNATURE-----":
        return True
    return False


def check_encryption_and_signature(gpg, data):
    """
    :param gpg:
    :param data:
    :return:
    """

    result = gpg.decrypt(data)

    # plain text message
    if result.status == 'no data was provided' and result.trust_text is None:
        return Encryption.missing, Signature.missing, ''

    # correct encrypted, signature missing
    if result.status == 'decryption ok' and result.trust_text is None and '-----BEGIN PGP SIGNATURE-----' not in result.data.decode('utf-8'):
        return Encryption.correct, Signature.missing, ''

    # correct encrypted, signature wrong
    if result.status == 'decryption ok' and result.trust_text is None and '-----BEGIN PGP SIGNATURE-----' in result.data.decode('utf-8'):
        sig_verify = gpg.verify(result.data)
        return Encryption.correct, Signature.incorrect, ' the signature failed to verify because {}'.format(sig_verify.status)

    # correct encrypted, correct signature
    if result.status == 'decryption ok' and result.trust_text is not None:
        return Encryption.correct, Signature.correct, ''

    # incorrect encrypted, signature can not be checked
    if result.status == 'decryption failed':
        return Encryption.incorrect, Signature.missing, result.status

    # not encrypted, correct signature
    if result.status == 'signature valid':
        return Encryption.missing, Signature.correct, ''

    # not encrypted, could not verify signature - todo there might be other cases here
    if result.status == 'no public key':
        reason_pubkey = 'we cound not find your public key! Did you attach it or put it on a keyserver?'
        return Encryption.missing, Signature.incorrect, reason_pubkey

    return Encryption.incorrect, Signature.incorrect, 'FAILURE {}'.format(result.status)


def verify_external_sig(gpg, data, sig):
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(sig)
        tmp.flush()
        result = gpg.verify_data(tmp.name, data)

    if result.status == 'no data was provided' and result.trust_text is None:
        return Signature.missing, ''

    if result.status == 'signature valid':
        return Signature.correct, ''

    if result.status == 'no public key':
        reason_pubkey = 'we could not find your public key! Did you attach it or put it on a keyserver?'
        return Signature.incorrect, reason_pubkey

    return Signature.incorrect, 'FAILURE {}'.format(result.status)



def select_response_encryption(key_status, encryption_status, signature_status):
    # A: Plaintext with no signature.
    if encryption_status == Encryption.missing and signature_status == Signature.missing:
        return ResponseEncryption.plain

    # I: Ciphertext, decryption fails. Key is available
    if encryption_status == Encryption.incorrect and key_status == PublicKey.available:
        return ResponseEncryption.encrypt_and_sign
    # D, G: Unsigned ciphertext with key not found. Sign response but cannot encrypt. 
    if encryption_status == Encryption.correct and key_status == PublicKey.not_available:
        return ResponseEncryption.encrypt_fails_but_sign
    # H: Unsigned ciphertext and we found their key.
    if encryption_status == Encryption.correct and signature_status == Signature.missing and key_status == PublicKey.available:
        return ResponseEncryption.encrypt_and_sign
    # F: Signed ciphertext with key found and signature verified
    if encryption_status == Encryption.correct and signature_status == Signature.correct:
        return ResponseEncryption.encrypt_and_sign

    # for all other cases, just sign the message
    return ResponseEncryption.sign


def encrypt_response(gpg, encryption_type, text, recipient):
    if encryption_type == ResponseEncryption.sign:
        return gpg.sign(text).data.decode("UTF-8")
    elif encryption_type == ResponseEncryption.encrypt_and_sign:
        return gpg.encrypt(text, recipients=recipient, always_trust=True, sign=True).data.decode("UTF-8")
    elif encryption_type == ResponseEncryption.encrypt_fails_but_sign:
        text += '\n\nNote: We could not find your public key! Was it attached or put on a keyserver?\nWe need your public key to encrypt emails to you.'
        return gpg.sign(text).data.decode("UTF-8")
    else:
        return text


#class CryptResult:
#    def __init__(self):



@contextmanager
def init_gpg(path_to_buddy_keyring):
    with temp_pgp_dir(path_to_buddy_keyring) as gnupghome:
        gpg = gnupg.GPG(gnupghome=gnupghome)
        gpg.encoding = 'utf-8'
        yield gpg


@contextmanager
def temp_pgp_dir(gpghome):

    # create temporary directory
    tmpdir = tempfile.mkdtemp(prefix="buddy_")

    # copy keyring to the temporary directory
    shutil.copyfile(path.join(gpghome, "pubring.gpg"), path.join(tmpdir, "pubring.gpg"))
    shutil.copyfile(path.join(gpghome, "secring.gpg"), path.join(tmpdir, "secring.gpg"))

    try:
        yield tmpdir
    finally:
        # automatically delete the directory
        shutil.rmtree(tmpdir)