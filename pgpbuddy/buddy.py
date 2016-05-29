import logging

import pgpbuddy.crypto as crypto
import pgpbuddy.response as response
from pgpbuddy.send import create_message, send_response
from pgpbuddy.fetch import fetch_messages, parse_message


log = logging.getLogger(__name__)


def handle_message(gpg, message):
    raw_message, header, body, attachments = message

    # try to import senders public key from keyserver
    crypto.import_public_keys_from_server(gpg, header["From"])

    # the original message was an S/MIME message (encrypted)
    if header["Content-Type"] == "multipart/encrypted":
        encryption_status, signature_status, reason = handle_multipart_encrypted(gpg, body)

    # the original message was an S/MIME message (signed)
    elif header["Content-Type"] == "multipart/signed":
        encryption_status, signature_status, reason = handle_multipart_signed(gpg, body, attachments)

    # plain text or inline/PGP message
    else:
        encryption_status, signature_status, reason = handle_inline_pgp(gpg, body, attachments)

    # Log messages that are not handled
    if 'FAILURE' in reason:
        log.info("Encryption and Signature incorrect for message: {}".format(raw_message))

    return header, encryption_status, signature_status, reason


def handle_multipart_encrypted(gpg, body):
    encryption_status, signature_status, reason = crypto.check_encryption_and_signature(gpg, body)

    if encryption_status != crypto.Encryption.correct:
        return encryption_status, signature_status, reason

    # parse the decrypted data into body and attachments
    result = gpg.decrypt(body)
    _, _, body, attachments = parse_message(result.data)

    # attachments might contain public key
    attachments = [crypto.decrypt_attachment(gpg, attachment) for attachment in attachments]
    crypto.import_public_keys_from_attachments(gpg, attachments)

    return encryption_status, signature_status, reason


def handle_multipart_signed(gpg, body, attachments):
    # there should be only one "attachment" which contains the signature
    signature = attachments[0]
    signature_status, reason = crypto.verify_external_sig(gpg, body, signature.encode())

    if signature_status != crypto.Signature.correct:
        return crypto.Encryption.missing, signature_status, reason

    # the multipart/signed contains another multipart body, split that one into actual body and attachments
    _, _, body, attachments = parse_message(body)

    # attachments might contain public key
    attachments = [crypto.decrypt_attachment(gpg, attachment) for attachment in attachments]
    crypto.import_public_keys_from_attachments(gpg, attachments)

    return crypto.Encryption.missing, signature_status, reason


def handle_inline_pgp(gpg, body, attachments):
    # attachments might contain public key
    attachments = [crypto.decrypt_attachment(gpg, attachment) for attachment in attachments]
    crypto.import_public_keys_from_attachments(gpg, attachments)

    encryption_status, signature_status, reason = crypto.check_encryption_and_signature(gpg, body)
    return encryption_status, signature_status, reason


def make_response(gpg, header, encryption_status, signature_status, reason):
    target = header["From"]

    # need senders public key to encrypt response
    key_status = crypto.check_public_key_available(gpg, header["From"])

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
            header, encryption_status, signature_status, reason = handle_message(gpg, message)
            response_full = make_response(gpg, header, encryption_status, signature_status, reason)

        print(response_full["Subject"])
        send_response(config["smtp-server"], config["smtp-port"], config["username"],
                      config["password"], response_full)