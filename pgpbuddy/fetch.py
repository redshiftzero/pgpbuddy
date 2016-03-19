from contextlib import contextmanager
import base64
import quopri
import re

import pyzmail
import poplib


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
    message = pyzmail.parse.message_from_bytes(b'\n'.join(raw_message))

    # identify and decode main message body
    if message.text_part:
        body = decode(message.text_part)
    else:
        body = decode(message.html_part)

    # decode attachments
    attachments = [decode(part) for part in message.mailparts if not part.is_body]

    return message, body, attachments


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
    return re.match( r'text/.*; .*"', content_type)


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
