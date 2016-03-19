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
    conn.dele(message_id+1)

    return message


def parse_message(raw_message):
    message = pyzmail.parse.message_from_bytes(b'\n'.join(raw_message))

    # identify and decode main message body and attachments
    body = decode(message.text_part)
    attachments = [decode(part) for part in message.mailparts if not part.is_body]

    return message, body, attachments


def decode(message_part):
    content_transfer_encoding = message_part.part["Content-Transfer-Encoding"]
    charset = get_charset(message_part.part["Content-Type"])
    payload = message_part.part.get_payload()

    if content_transfer_encoding == "base64":
        return base64.b64decode(payload).decode(charset)
    elif content_transfer_encoding == "quoted-printable":
        return quopri.decodestring(payload).decode(charset)
    else:
        return payload


def get_charset(content_type):
    """
    Parse out charset from content type
    :param content_encoding: content type string, e.g. Content-Type: text/plain; charset="utf-8"
    :return:
    """
    m = re.match( r'text/plain; charset="(.*)"', content_type)
    if m:
        return m.group(1)
    else:
        return "ascii"


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
