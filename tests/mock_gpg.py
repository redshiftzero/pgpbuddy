from unittest.mock import MagicMock

import gnupg

from pgpbuddy.crypto import Encryption, Signature, PublicKey


############################################################
# mock encryption and decryption
############################################################

def mock_encrypt(success):
    if success:
        result = MagicMock(gnupg.Crypt)
        result.ok = True
    else:
        result = MagicMock(gnupg.Crypt)
        result.ok = False
    return MagicMock(return_value=result)


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

    return MagicMock(return_value=result)


# use this mock to test dealing with unexpected outputs from python_gnupg
def mock_decrypt_unexpected_output():
    result = MagicMock(gnupg.Crypt)
    result.status = 'random noise'
    return MagicMock(return_value=result)

############################################################################
# mock verifying data
############################################################################


def mock_verify(signature_status, public_key_status=None):
    if signature_status == Signature.missing:
        result = MagicMock(gnupg.Verify)
        result.valid = False
        result.status = None
        result.key_id = None
    elif signature_status == Signature.incorrect:
        if public_key_status and public_key_status == PublicKey.not_available:
            result = MagicMock(gnupg.Verify)
            result.valid = False
            result.status = 'no public key'
        else:
            result = MagicMock(gnupg.Verify)
            result.valid = False
            result.status = 'unexpected data'
    else:
        result = MagicMock(gnupg.Verify)
        result.valid = True
        result.status = 'signature valid'
        result.key_id = "1234"
    return MagicMock(return_value=result)

############################################################################
# mock import public keys
############################################################################


def mock_import_keys(list_of_success_indicators):
    """
    :param list_of_success_indicators: A boolean or a list of booleans. The i-th element indicates whether
    import_keys should succeed or fail on the i-th time it is being called.
    :return:
    """

    def get_result(success):
        if success:
            result = MagicMock(gnupg.ImportResult)
            result.results = [{'ok': '1'}]
        else:
            result = MagicMock(gnupg.ImportResult)
            result.results = [{'ok': '0'}]
        return result

    return init_multicall_mock(get_result, list_of_success_indicators)


def mock_search_keys(keys_to_return):
    result = [{"keyid": key} for key in keys_to_return]
    return MagicMock(return_value=result)


def mock_recv_keys():
    return MagicMock(return_value=None)


###############################################################################
# utils
###############################################################################

def init_multicall_mock(mock_method, list_of_configs):
    """
    Sometimes the mocked method will be called several times by the function under test. Use this method to enable
    multiple calls to the same method, Supply a list of configurations - the i-th element configures the mock method
    for the ith-call.
    :param mock_method:
    :param list_of_configs:
    :return:
    """
    if not isinstance(list_of_configs, list):
        list_of_configs = [list_of_configs]

    def side_effect(*args):
        return mock_method(list_of_configs.pop(0))

    return MagicMock(side_effect=side_effect)
