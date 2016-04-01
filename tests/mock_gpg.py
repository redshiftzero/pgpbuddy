from unittest.mock import MagicMock

import gnupg

from pgpbuddy.crypto import Encryption, Signature

############################################################
# mock decryption
############################################################

def mock_decrypt(encryption_status, signature_status):

    if encryption_status == Encryption.correct:
        if signature_status == Signature.correct:
            result = MagicMock(gnupg.Crypt)
            result.status = 'decryption ok'
            result.trust_text = 'much trusted'

        if signature_status == Signature.incorrect:
            result = MagicMock(gnupg.Crypt)
            result.status = 'decryption ok'
            result.trust_text = None
            result.data = b'-----BEGIN PGP SIGNATURE-----'

        if signature_status == Signature.missing:
            result = MagicMock(gnupg.Crypt)
            result.status = 'decryption ok'
            result.trust_text = None
            result.data = b''

    if encryption_status == Encryption.incorrect:
        result = MagicMock(gnupg.Crypt)
        result.status = 'decryption failed'

    if encryption_status == Encryption.missing:
        if signature_status == Signature.correct:
            result = MagicMock(gnupg.Verify)
            result.status = 'signature valid'

        if signature_status == Signature.incorrect:
            result = MagicMock(gnupg.Verify)
            result.status = 'no public key'

        if signature_status == Signature.missing:
            result = MagicMock(gnupg.Verify)
            result.status = 'no data was provided'
            result.trust_text = None

    return lambda data: result


# use this mock to test dealing with unexpected outputs from python_gnupg
def mock_decrypt_unexpected_output():
    result = MagicMock(gnupg.Crypt)
    result.status = 'random noise'
    return lambda data: result

#############################################################################
# mock import public keys
############################################################################


def mock_import_keys(success):
    if success:
        result = MagicMock(gnupg.ImportResult)
        result.results = [{'ok': '1'}]
    else:
        result = MagicMock(gnupg.ImportResult)
        result.results = [{'ok': '0'}]
    return lambda key: result