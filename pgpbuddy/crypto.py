from contextlib import contextmanager
import shutil
import tempfile
from os import path
from enum import Enum

import gnupg

PublicKey = Enum('PublicKey', 'available not_available')
Signature = Enum('Signature', 'correct incorrect missing')
Encryption = Enum('Encryption', 'correct incorrect missing')


def import_public_key(gpg, sender):
    keys = gpg.search_keys(sender, "pgp.mit.edu")
    if not keys:
        return PublicKey.not_available

    # add keys to keyring
    for key in keys:
        gpg.recv_keys("pgp.mit.edu", key["keyid"])

    return PublicKey.available


def decrypt(gpg, msg):
    data = msg.get_payload()
    result = gpg.decrypt(data)

    if result.ok and result.status == "decryption ok":
        return Encryption.correct

    if result.status == "decryption failed":
        return Encryption.incorrect

    return Encryption.missing


def verify_signature(gpg, msg):
    data = msg.get_payload()

    # first verify signature assuming that the message has been encrypted
    result = gpg.decrypt(data)
    if result.trust_text:
        return Signature.correct

    # this failed, try again but assume it has not been encrypted
    result = gpg.verify(data)
    if result.trust_text:
        return Signature.correct

    return Signature.missing   # todo is this correct? when does incorrect happen?


def sign_and_or_decrypt_message(target, body_text, gpg, key_status, encryption_status, signature_status):
    def encrypt_and_sign():
        # as per python_gnupgp documentation, recipient must be trusted, otherwise pgp call silently fails
        return gpg.encrypt(body_text, recipients=target, always_trust=True, sign=True).data.decode("UTF-8")

    def sign():
        return gpg.sign(body_text).data.decode("UTF-8")

    # A: Plaintext with no signature.
    if encryption_status == Encryption.missing and signature_status == Signature.missing:
        return body_text

    # I: Ciphertext, decryption fails. Key is available
    if encryption_status == Encryption.incorrect and key_status == PublicKey.available:
        return encrypt_and_sign()
    # H: Unsigned ciphertext and we found their key.
    if encryption_status == Encryption.correct and signature_status == Signature.missing and key_status == PublicKey.available:
        return encrypt_and_sign()
    # F: Signed ciphertext with key found and signature verified
    if encryption_status == Encryption.correct and signature_status == Signature.correct:
        return encrypt_and_sign()

    # for all other cases, just sign the message
    return sign()

    """
    if encryption_status == Encryption.missing:
        if signature_status == Signature.missing:
            # A: Plaintext with no signature.
            return body_text
        if signature_status != Signature.missing and key_status == PublicKey.not_available:
            # B: Plaintext with signature but cannot find their public key to verify the signature.
            return sign(body_text)
        if signature_status == Signature.incorrect:
            # C: Plaintext with signature but signature fails to verify
            return sign(body_text)
        if signature_status == Signature.correct:
            # E: Plaintext with signature and signature verifies.
            return sign(body_text)

    elif encryption_status == Encryption.incorrect:
        if key_status == PublicKey.not_available:
            # J: Ciphertext, decryption fails, and we can't find their public key.
            return sign(body_text)
        if key_status == PublicKey.available:
            # I: Ciphertext, decryption fails. Return failure and reason why decrypt fails.
            return encrypt_and_sign(body_text)

    elif encryption_status == Encryption.correct:
        if signature_status == Signature.missing:
            if key_status == PublicKey.available:
                # H: Unsigned ciphertext and we found their key.
                return encrypt_and_sign(body_text)
            if key_status == PublicKey.not_available:
                # G: Unsigned ciphertext with key not found.
                return sign(body_text)
        if signature_status != Signature.missing:
            if signature_status == Signature.correct:
                # F: Signed ciphertext with key found and signature verified
                return encrypt_and_sign(body_text)
            else:
                # D: Signed ciphertext with signature not verified either because of an error or because we cannot find their key.
                return sign(body_text)
    """


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