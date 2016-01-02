from contextlib import contextmanager
import smtplib
import gnupg


def send_message(smtp_server, smtp_port, username, password, target):
    with connect(smtp_server, smtp_port, username, password) as conn:
        email_body = "Subject: PLAINTEXT.\nYOU'VE SENT PLAINTEXT"
        conn.sendmail(username, target, email_body)


@contextmanager
def connect(smtp_server, smtp_port, username, password):
    try:
        conn = smtplib.SMTP_SSL(smtp_server, smtp_port)
        conn.ehlo()
        conn.login(username, password)
        yield conn
    finally:
        if conn:
            conn.quit()