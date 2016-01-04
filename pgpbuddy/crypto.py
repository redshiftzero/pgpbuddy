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