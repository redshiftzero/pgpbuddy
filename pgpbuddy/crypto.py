from contextlib import contextmanager
import shutil
import tempfile
import re
from os import path

import gnupg


class NoMatchingPublicKey(Exception):
    pass


class InvalidSignature(Exception):
    pass

regexp_enc = re.compile(r'BEGIN PGP MESSAGE')
regexp_sig = re.compile(r'BEGIN PGP SIGNED')

@contextmanager
def init_gpg(path_to_buddy_keyring):
    with temp_pgp_dir(path_to_buddy_keyring) as gnupghome:
        gpg = gnupg.GPG(gnupghome=gnupghome)
        gpg.encoding = 'utf-8'
        yield gpg


def is_encrypted(msg):
    if regexp_enc.search(str(msg)):
        return True
    return False


def is_signed(msg):
    if regexp_sig.search(str(msg)):
        return True
    return False


def decrypt(gpg, msg):
    data = msg.get_payload()
    return gpg.decrypt(data)


def download_public_key(gpg, sender):
    keys = gpg.search_keys(sender, "pgp.mit.edu")
    if not keys:
        raise NoMatchingPublicKey()
    # add keys to keyring
    for key in keys:
        gpg.recv_keys("pgp.mit.edu", key["keyid"])


def verify_signature(gpg, msg):
    data = msg.get_payload()
    result = gpg.verify(data)
    if not result.trust_text:
        raise InvalidSignature()


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
        pass