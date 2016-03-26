from contextlib import contextmanager
import base64
import quopri
import re

import pyzmail
import poplib


class ParsingError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "Error parsing message, {}".format(self.msg)


def fetch_messages(pop3_server, username, password):
    with connect(pop3_server, username, password) as conn:
        num_messages = len(conn.list()[1])
        message_ids = list(range(num_messages))
        messages = [retrieve_message(conn, msg_id) for msg_id in message_ids]
        messages = [parse_message(raw_msg) for raw_msg in messages]
        return messages


def retrieve_message(conn, message_id):
    # messages are counted starting at 1 
    message = conn.retr(message_id+1)[1]

    # once buddy has the message we can delete the original
    # conn.dele(message_id+1)

    return message


def parse_message(raw_message):
    if isinstance(raw_message, list):
        raw_message = b'\n'.join(raw_message)
    message = pyzmail.parse.message_from_bytes(raw_message)

    # extract and decode relevant parts of header
    headers = {"Subject": pyzmail.parse.decode_mail_header(message["Subject"]),
               "To": pyzmail.parse.decode_mail_header(message["To"]),
               "From": pyzmail.parse.decode_mail_header(message["From"]),
               "Content-Type": message.get_content_type()}

    # extract and decode body and attachments
    if message.get_content_type() == "multipart/encrypted":
        body, attachments = parse_multipart_encrypted(message)
    elif message.get_content_type() == "multipart/signed":
        body, attachments = parse_multipart_signed(raw_message, message)
    else:
        body, attachments = parse_pgp_inline(message)

    return raw_message, headers, body, attachments


def parse_multipart_encrypted(message):
    # multipart/encrypted must contain exactly two parts: I) version and other metadata, II) message body
    # attachements are encrypted and part of the message body
    if len(message.mailparts) != 2:
        raise ParsingError("Malformated S/MIME message")

    # body must always be application/octet-stream, there can only be one application/octet stream part
    possible_bodies = [part for part in message.mailparts if "application/octet-stream" in part.type]
    if len(possible_bodies) != 1:
        raise ParsingError("Malformated S/MIME message")
    body = possible_bodies[0]

    return decode(body), []


def parse_multipart_signed(raw_message, parsed_message):
    # multipart/signed contains several boundaries. this confuses pyzmail.
    # have to split message manually to find multipart/mixed
    boundary = parsed_message.get_boundary().encode()
    parts = raw_message.split(b'\n--'+boundary+b'\n')

    # multipart/signed must contained one and only one multipart/mixed part,
    possible_bodies = [part for part in parts if b'Content-Type: multipart/mixed' in part]
    if len(possible_bodies) != 1:
        raise ParsingError("Malformated S/MIME message")
    body = possible_bodies[0]

    # multipart/signed must contain one and only one application/pgp-signature
    # this one pyzmail finds correctly
    possible_signatures = [part.part.get_payload() for part in parsed_message.mailparts
                           if part.part.get_content_type() == 'application/pgp-signature']
    if len(possible_signatures) != 1:
        raise ParsingError("Malformated S/MIME message")

    return body, possible_signatures

def parse_pgp_inline(message):
    # identify and decode main message body
    if message.text_part:
        body = decode(message.text_part)
    elif message.html_part:
        body = decode(message.html_part)
    else:
        raise ParsingError("Email does not contain body")

    # decode attachments
    attachments = [decode(part) for part in message.mailparts if not part.is_body]
    return body, attachments


def decode(message_part):
    content_transfer_encoding = message_part.part["Content-Transfer-Encoding"]
    content_type = message_part.part["Content-Type"]
    payload = message_part.part.get_payload()

    if content_transfer_encoding == "base64":
        payload = base64.b64decode(payload)
    elif content_transfer_encoding == "quoted-printable":
        payload = quopri.decodestring(payload)

    # payload is already properly decoded, usually happens in plain text emails
    if isinstance(payload, str):
        return payload

    # payload is text, decode with proper charset
    if is_text(content_type):
        return payload.decode(get_charset(content_type))

    # payload is probably binary, don't do anything else
    return payload


def is_text(content_type):
    return re.match(r'text/.*; .*', content_type)


def get_charset(content_type):
    m = re.match( r'text/.*; charset="(.*)"', content_type)
    if m:
        return m.group(1)
    else:
        return "UTF-8"


@contextmanager
def connect(pop3_server, username, password):
    try:
        conn = poplib.POP3_SSL(pop3_server)
        conn.user(username)
        conn.pass_(password)
        yield conn
    finally:
        if conn:
            conn.quit()
