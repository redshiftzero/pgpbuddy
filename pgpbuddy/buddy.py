import logging

import pgpbuddy.crypto as crypto
import pgpbuddy.response as response
from pgpbuddy.send import create_message, send_response
from pgpbuddy.fetch import fetch_messages, parse_message


log = logging.getLogger(__name__)


def handle_message(gpg, message):
    raw_message, header, body, attachments = message

    target = header["From"]
    crypto.import_public_keys_from_server(gpg, header["From"])

    # the original message was an S/MIME message (encrypted)
    if header["Content-Type"] == "multipart/encrypted":
        encryption_status, signature_status, reason = decrypt_multipart_encrypted(gpg, body)

    # the original message was an S/MIME message (signed)
    elif header["Content-Type"] == "multipart/signed":
        possible_signatures = [a for a in attachments if crypto.contains_signature(a)]
        result = gpg.verify_data(possible_signatures[0], body.encode())
        print(result.stderr)
        
    # plain text or inline/PGP message
    else:
        attachments = [crypto.decrypt_attachment(gpg, attachment) for attachment in attachments]
        crypto.import_public_keys_from_attachments(gpg, attachments)
        encryption_status, signature_status, reason = crypto.check_encryption_and_signature(gpg, body, attachments)

    key_status = crypto.check_public_key_available(gpg, header["From"])

    # Log messages that are not handled
    if 'FAILURE' in reason:
        log.info("Encryption and Signature incorrect for message: {}".format(raw_message))

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


def decrypt_multipart_encrypted(gpg, body):
    encryption_status, signature_status, reason = crypto.check_encryption_and_signature(gpg, body, [])

    # the message was correctly encrypted, parse the decrypted data into body and attachments
    # because attachments might contain public key
    if encryption_status == crypto.Encryption.correct:
        result = gpg.decrypt(body)
        _, _, body, attachments = parse_message(result.data)

        # todo this should not be necessary. fix when re-factoring crypto
        attachments = [crypto.decrypt_attachment(gpg, attachment) for attachment in attachments]

        crypto.import_public_keys_from_attachments(gpg, attachments)

    return encryption_status, signature_status, reason


def check_and_reply_to_messages(config):
    messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
    for message in messages:
        with crypto.init_gpg(config["gnupghome"]) as gpg:
            response_full = handle_message(gpg, message)
        print(response_full["Subject"])
        #send_response(config["smtp-server"], config["smtp-port"], config["username"],
        #              config["password"], response_full)