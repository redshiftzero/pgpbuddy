from pgpbuddy.crypto import *
from pgpbuddy.response import *
from pgpbuddy.send import create_message
from pgpbuddy.fetch import fetch_messages


def handle_message(gpg, msg):
    target = msg["From"]

    key_status = import_public_key(gpg, msg["From"])
    encryption_status, signature_status = check_encryption_and_signature(gpg, msg)

    response_subject = subject[(encryption_status.value, signature_status.value)]
    response_subject = "{} (Was: {})".format(response_subject, msg["Subject"])

    response_text = content[(encryption_status.value, signature_status.value)]
    response_encryption = select_response_encryption(key_status, encryption_status, signature_status)
    response_text = encrypt_response(gpg, response_encryption, response_text, target)

    response = create_message(target, response_subject, response_text)
    return response


def check_and_reply_to_messages(config):
    messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
    for msg in messages:
        with init_gpg(config["gnupghome"]) as gpg:
            response = handle_message(gpg, msg)
        print(response["Subject"])
        #send_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"], response)