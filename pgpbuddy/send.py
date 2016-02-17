from contextlib import contextmanager
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


log = logging.getLogger(__name__)


def create_message(recipient, subject, content):
    msg = MIMEMultipart('alternative')
    msg['From'] = 'PGPBuddy <buddy@pgp.today>'
    msg['To'] = recipient
    msg['Subject'] = subject
    body_text = content
    body_text = MIMEText(body_text, 'plain')
    msg.attach(body_text)
    return msg


def send_response(smtp_server, smtp_port, username, password, msg):
    with connect(smtp_server, smtp_port, username, password) as conn:
        conn.sendmail(username, msg["To"], msg.as_string())
        log.debug('Sent email successfully')



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

