from contextlib import contextmanager
import base64
import quopri

import pyzmail
import poplib


def fetch_messages(pop3_server, username, password):
    with connect(pop3_server, username, password) as conn:
        num_messages = len(conn.list()[1])
        message_ids = list(range(num_messages))
        messages = [retrieve_message(conn, msg_id) for msg_id in message_ids]
        return messages


def retrieve_message(conn, message_id):
    # messages are counted starting at 1 
    message = conn.retr(message_id+1)[1]
    message = pyzmail.parse.message_from_bytes(b'\n'.join(message))

    # once buddy has the message we can delete the original
    conn.dele(message_id+1)

    # identify main message body and attachments
    body = message.text_part
    attachments = [decode_attachment(part) for part in message.mailparts if not part.is_body]

    return message, body, attachments


def decode_attachment(attachment):
    if attachment.part["Content-Transfer-Encoding"] == "base64":
        return base64.b64decode(attachment.part.get_payload())
    elif attachment.part["Content-Transfer-Encoding"] == "quoted-printable":
        return quopri.decodestring(attachment.part.get_payload()).decode("UTF-8")
    else:
        return attachment.part.get_payload(decode=True)

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
