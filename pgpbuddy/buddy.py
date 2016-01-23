from pgpbuddy.crypto import *
from pgpbuddy.send import *


def handle_message(gpg, msg):
    target = msg["From"]

    key_status = import_public_key(gpg, msg["From"])
    encryption_status, signature_status = check_encryption_and_signature(gpg, msg)

    response_subject = subject[(encryption_status.value, signature_status.value)]
    response_subject = "{} (Was: {})".format(response_subject, msg["Subject"])
    print(response_subject)

    response_text = content[(encryption_status.value, signature_status.value)]
    response_encryption = select_response_encryption(key_status, encryption_status, signature_status)
    response_text = encrypt_response(gpg, response_encryption, response_text, target)

    response = create_message(target, response_subject, response_text)
    return response

