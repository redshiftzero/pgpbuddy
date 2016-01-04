import yaml
import pdb

from pgpbuddy.fetch import fetch_messages
from pgpbuddy.crypto import *
from pgpbuddy.send import send_response, get_message


def select_response(gpg, msg):
    if is_encrypted(msg):
        decrypted_message = decrypt(gpg, msg)

        if is_signed(decrypted_message):   # todo this check does not work
            ## check valid sig TODO
            return get_message('encrypted_signed')
        else:
            return get_message('encrypted_success')

    elif is_signed(msg):
        try:
            download_public_key(gpg, msg["From"])
        except NoMatchingPublicKey:
            return get_message('signed_fail')

        try:
            verify_signature(gpg, msg)
        except InvalidSignature:
            return get_message('signed_fail')

        return get_message('signed_success')

    else:
        return get_message('plaintext')


def load():
    with open("config.yaml", 'r') as config:
        config = yaml.load(config)

        with init_gpg(config["gnupghome"]) as gpg:
            messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
            for msg in messages:
                print(msg["Subject"])
                target = msg["From"]
                response = select_response(gpg, msg)
                print(response["Subject"]+"\n")
                send_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"],
                              target, response)


if __name__=='__main__':
    load()