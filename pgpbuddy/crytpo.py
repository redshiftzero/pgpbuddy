import re
import gnupg

regexp_enc = re.compile(r'BEGIN PGP MESSAGE')
regexp_sig = re.compile(r'BEGIN PGP SIGNED')

def init_gpg(gnupghome):
    gpg = gnupg.GPG(gnupghome=gnupghome)
    gpg.encoding = 'utf-8'
    return gpg


def is_encrypted(msg):
    if regexp_enc.search(str(msg)):
        return True
    return False


def is_signed(msg):
    if regexp_sig.search(str(msg)):
        return True
    return False


def decrypt_message(gpg, msg):
    data = msg.get_payload()      # todo multi-part messages
    return gpg.decrypt(data)

