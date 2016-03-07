import pgpbuddy.crypto as crypto
import pgpbuddy.response as response
from pgpbuddy.send import create_message, send_response
from pgpbuddy.fetch import fetch_messages


def handle_message(gpg, message):
    header, body, attachments = message
    target = header["From"]

    attachments = [crypto.decrypt_attachment(gpg, attachment) for attachment in attachments]

    crypto.import_public_keys_from_attachments(gpg, attachments)
    crypto.import_public_keys_from_server(gpg, header["From"])

    key_status = crypto.check_public_key_available(gpg, header["From"])
    encryption_status, signature_status, reason = crypto.check_encryption_and_signature(gpg, body, attachments)

    response_subject = response.subject[(encryption_status.value, signature_status.value)]
    response_subject = "{} (Was: {})".format(response_subject, header["Subject"])

    response_text = response.content[(encryption_status.value, signature_status.value)]

    # Append reason if exists
    if reason != '':
        response_text = '{} because {}'.format(response_text, reason)
    response_encryption = crypto.select_response_encryption(key_status, encryption_status, signature_status)
    response_text = crypto.encrypt_response(gpg, response_encryption, response_text, target)

    response_full = create_message(target, response_subject, response_text)
    return response_full


def check_and_reply_to_messages(config):
    messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
    for message in messages:
        with crypto.init_gpg(config["gnupghome"]) as gpg:
            response_full = handle_message(gpg, message)
        print(response_full["Subject"])
        send_response(config["smtp-server"], config["smtp-port"], config["username"], 
                      config["password"], response_full)