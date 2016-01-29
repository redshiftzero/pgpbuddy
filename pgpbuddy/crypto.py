from contextlib import contextmanager
import shutil
import tempfile
from os import path
from enum import Enum

import gnupg

PublicKey = Enum('PublicKey', 'available not_available')
Signature = Enum('Signature', 'correct incorrect missing')
Encryption = Enum('Encryption', 'correct incorrect missing')
ResponseEncryption = Enum('ResponseEncryption', 'plain sign encrypt_and_sign')


def import_public_keys_from_attachments(gpg, attachments):
    def contains_public_key_block(data):
        data = data.strip().split("\n")
        if data[0] == "-----BEGIN PGP PUBLIC KEY BLOCK-----" and data[-1] == "-----END PGP PUBLIC KEY BLOCK-----":
            return True
        return False

    def decrypt_if_necessary(data):
        result = gpg.decrypt(data)
        if result.status == 'decryption_ok':
            return result.data.decode("UTF-8")
        else:
            return data

    def try_import(attachment):
        payload = attachment.get_payload().decode('UTF-8')
        payload = decrypt_if_necessary(payload)
        if contains_public_key_block(payload):
            result = gpg.import_keys(payload)
            if result.results[0]['ok'] == '1':
                return True
        return False

    imported = [i for i, attach in enumerate(attachments) if try_import(attach)]
    remaining_attachments = [attach for i, attach in enumerate(attachments) if i not in imported]
    return remaining_attachments


def import_public_keys_from_server(gpg, sender):
    keys = gpg.search_keys(sender, "pgp.mit.edu")
    if not keys:
        return PublicKey.not_available

    # add keys to keyring
    for key in keys:
        gpg.recv_keys("pgp.mit.edu", key["keyid"])

    return PublicKey.available


def check_encryption_and_signature(gpg, msg):
    data = msg.get_payload()
    result = gpg.decrypt(data)

    # plain text message
    if result.status == 'no data was provided' and result.trust_text is None:
        return Encryption.missing, Signature.missing

    # correct encrypted, signature missing or wrong
    # todo figure out how to distinguish those two cases
    if result.status == 'decryption ok' and result.trust_text is None:
        return Encryption.correct, Signature.missing

    # correct encrypted, correct signature
    if result.status == 'decryption ok' and result.trust_text is not None:
        return Encryption.correct, Signature.correct

    # incorrect encrypted, signature can not be checked
    if result.status == 'decryption failed':
        return Encryption.incorrect, Signature.missing

    # not encrypted, correct signature
    if result.status == 'signature valid':
        return Encryption.missing, Signature.correct

    # not encrypted, could not verify signature - todo there might be other cases here
    if result.status == 'no public key':
        return Encryption.misssing, Signature.incorrect

    # todo might want to introduce a specific fallback response here
    # also should log result so that we can reproduce later
    return Encryption.incorrect, Signature.incorrect


def select_response_encryption(key_status, encryption_status, signature_status):
    # A: Plaintext with no signature.
    if encryption_status == Encryption.missing and signature_status == Signature.missing:
        return ResponseEncryption.plain

    # I: Ciphertext, decryption fails. Key is available
    if encryption_status == Encryption.incorrect and key_status == PublicKey.available:
        return ResponseEncryption.encrypt_and_sign
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
    else:
        return text


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