from contextlib import contextmanager
import smtplib
import gnupg


def plaintext_response(smtp_server, smtp_port, username, password, target):
    with connect(smtp_server, smtp_port, username, password) as conn:
        email_body = "Subject: PLAINTEXT.\nYOU'VE SENT PLAINTEXT"
        conn.sendmail(username, target, email_body)


def encrypted_response(smtp_server, smtp_port, username, password, target):
    with connect(smtp_server, smtp_port, username, password) as conn:
        email_body = "Subject: ENCRYPTED.\nSUCCESS!! YOU'VE SENT ENCRYPTED"
        conn.sendmail(username, target, email_body)


def signed_response(smtp_server, smtp_port, username, password, target):
    with connect(smtp_server, smtp_port, username, password) as conn:
        email_body = "Subject: SIGNED.\nSUCCESS!! YOU'VE SENT A SIGNED MESSAGE!!"
        conn.sendmail(username, target, email_body)


def encryptsigned_response(smtp_server, smtp_port, username, password, target):
    with connect(smtp_server, smtp_port, username, password) as conn:
        email_body = "Subject: SIGNED AND ENCRYPTED.\nSUCCESS!! YOU GOT IT!"
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