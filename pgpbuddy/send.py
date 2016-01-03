from contextlib import contextmanager
import smtplib
import gnupg

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


content = {'signed_success': 'Welcome to PGPBuddy! You\'ve correctly signed an email to me!',
    'encrypted_signed_success': 'You\'ve correctly signed and encrypted an email to me!',
    'encrypted_success': 'You\'ve correctly encrypted an email to me!',
    'plaintext': ('Welcome to PGPBuddy! It looks like you\'ve sent plaintext '
                  '(clear, unencrypted text).\n\n'
                  'To get started, set up PGP using one of these tutorials from '
                  'the Electronic Frontier Foundation: \n\n'
                  'Windows: https://ssd.eff.org/en/module/how-use-pgp-windows\n'
                  'Mac OS X: https://ssd.eff.org/en/module/how-use-pgp-mac-os-x\n'
                  'Linux: https://ssd.eff.org/en/module/how-use-pgp-linux\n\n'
                  'Once you have your key ready, send me an encrypted and/or signed '
                  'email and I\'ll check things are working!')}


subject = {'signed_success': 'PGP email successfully signed! (not encrypted)',
    'encrypted_signed_success': 'PGP email successfully signed and encrypted!',
    'encrypted_success': 'PGP email successfully encrypted! (not signed)',
    'plaintext': 'Unencrypted, unsigned email detected'}


def get_message(response_code):
    msg = MIMEMultipart('alternative')
    msg['From'] = 'pgpbuddy'
    msg['Subject'] = subject[response_code]
    body_text = MIMEText(content[eresponse_code], 'plain')
    msg.attach(body_text)
    return msg


def send_response(smtp_server, smtp_port, username, password, target, msg):
    with connect(smtp_server, smtp_port, username, password) as conn:
        msg['To'] = target
        conn.sendmail(username, target, msg.as_string())
    return None


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