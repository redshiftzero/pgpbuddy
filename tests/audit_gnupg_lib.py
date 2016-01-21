from os import path
from contextlib import contextmanager

import gnupg

from pgpbuddy.crypto import temp_pgp_dir


"""
To use this module, you first need to generate a bunch of pgp keys. A convenient script to do so can be found in the
test_credentials directory.

cd test_credentials
./generate_keys.sh

Code to create an expired key is uncommented in the script. Please check those out as well.
"""

credentials_dir = "test_credentials"
known_users = {"buddy": "buddy@example.com", "user1": "user1@example.com", "user2": "user2@test.nl"}


def decrypt_plain_text():
    data = "this is a plain text message"
    response = decrypt(data, recipient="buddy")

    print("##### Plain text")
    log_decrypt_response(response)


def decrypt_correct():
    data = "this will be encrypted"
    encrypted = encrypt(data, recipient="buddy")
    decrypted = decrypt(encrypted, recipient="buddy")

    print("##### Correctly encrypted")
    log_decrypt_response(decrypted)


def decrypt_wrong_recipient():
    data = "this will be encrypted"
    encrypted = encrypt(data, recipient="user2")
    decrypted = decrypt(encrypted, recipient="buddy")

    print("##### Encrypted with wrong recipient")
    log_decrypt_response(decrypted)



def verify_plain_text():
    data = "this is a plain text message"
    response = verify(data, "user1")

    print("##### Unsigned")
    log_verify_response(response)


def verify_correctly_signed():
    data = "this will be signed"
    signed = sign(data, "user1")
    response = verify(signed, "user1")

    print("##### Correctly signed")
    log_verify_response(response)


def verify_public_key_unknown():
    data = "this will be signed"
    signed = sign(data, "user1")
    response = verify(signed, "buddy")

    print("##### Signed, unknown public key")
    log_verify_response(response)

"""
def verify_expired_key():   # library does not seem to pick up on expired key
    signed = path.join(credentials_dir, "expired.sig")
    with open(signed, "rb") as signed:
        signed = signed.readlines()[0]
        response = verify(signed, "expired")

    print("##### Signed, with expired key")
    log_verify_response(response)
"""

def decrypt_and_verify_correct():
    data = "this will be encrypted and signed"
    encrypted_signed = encrypt_and_sign(data, sender="user1", recipient="buddy")
    response = decrypt_and_verify(encrypted_signed, sender="user1", recipient="buddy")

    print("##### Signed and encrypted")
    log_decrypt_response(response)


def decrypt_and_verify_wrong_recipient():
    data = "this will be encrypted and signed"
    encrypted_signed = encrypt_and_sign(data, sender="user1", recipient="user2")
    response = decrypt_and_verify(encrypted_signed, sender="user1", recipient="buddy")

    print("##### Signed and encrypted, wrong recipient (decrypt fails)")
    log_decrypt_response(response)


def decrypt_and_verify_unknown_public_key():
    data = "this will be encrypted and signed"
    encrypted_signed = encrypt_and_sign(data, sender="user1", recipient="buddy")
    response = decrypt_and_verify(encrypted_signed, sender="user2", recipient="buddy")

    print("##### Signed and encrypted, unkown sender public key (verify fails)")
    log_decrypt_response(response)


def decrypt_and_verify_wrong_recipient_unknown_public_key():
    data = "this will be encrypted and signed"
    encrypted_signed = encrypt_and_sign(data, sender="user1", recipient="buddy")
    response = decrypt_and_verify(encrypted_signed, sender="user2", recipient="user2")

    print("##### Signed and encrypted, wrong recipient, unkown sender public key (decrypt fails, verify fails)")
    log_decrypt_response(response)


def decrypt_and_verify_only_signed():
    data = "this will be signed but not encrypted"
    signed = sign(data, sender="user1")
    response = decrypt_and_verify(signed, sender="user1", recipient="user2")

    print("##### Signed but not encrypted")
    log_decrypt_response(response)

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


def decrypt(text, recipient):
    gpg = init_gpg(recipient)
    return gpg.decrypt(text)


def sign(text, sender):
    gpg = init_gpg(sender)
    return gpg.sign(text).data


def verify(text, sender):
    gpg = init_gpg(sender)
    return gpg.verify(text)


def encrypt_and_sign(text, sender, recipient):
    with merge_keyrings(sender, recipient) as gpg:
        return gpg.encrypt(text, recipients=[known_users[recipient]], always_trust=True, sign=sender).data


def decrypt_and_verify(text, sender, recipient):
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


if __name__ == '__main__':
    decrypt_plain_text()
    decrypt_correct()
    decrypt_wrong_recipient()

    verify_plain_text()
    verify_correctly_signed()
    verify_public_key_unknown()
    # verify_expired_key()

    decrypt_and_verify_correct()
    decrypt_and_verify_wrong_recipient()
    decrypt_and_verify_unknown_public_key()
    decrypt_and_verify_wrong_recipient_unknown_public_key()
    decrypt_and_verify_only_signed()
