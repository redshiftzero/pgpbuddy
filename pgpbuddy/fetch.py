from contextlib import contextmanager
import pyzmail
import poplib


class ErrorParsingMessage(Exception):
    pass


def fetch_messages(pop3_server, username, password):
    with connect(pop3_server, username, password) as conn:
        num_messages = len(conn.list()[1])
        message_ids = list(range(num_messages))
        messages = [retrieve_message(conn, msg_id) for msg_id in message_ids]
        return messages


def retrieve_message(conn, message_id):
    # messages are counted starting at 1 
    message = conn.retr(message_id+1)[1]
    message = [line.decode("UTF-8") for line in message]
    message = "\n".join(message)
    message = pyzmail.PyzMessage.factory(message)

    # once buddy has the message we can delete the original
    conn.dele(message_id+1)

    # identify main message body and attachments
    body = [part for part in message.mailparts if part.is_body == "text/plain"]
    attachments = [part for part in message.mailparts if not part.is_body]
    if len(body) > 1:
        raise ErrorParsingMessage("Several parts of the message could potentially be the body")

    return message, body[0], attachments

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
