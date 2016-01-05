import yaml
import pdb

from pgpbuddy.fetch import fetch_messages
from pgpbuddy.crypto import *
from pgpbuddy.send import send_response, get_response_message


def select_response(gpg, msg):

    key_status = import_public_key(gpg, msg["From"])
    encryption_status = decrypt(gpg, msg)
    signature_status = verify_signature(gpg, msg)

    target = msg["From"]
    response = get_response_message(target, gpg, key_status, encryption_status, signature_status)

    print(msg["Subject"])
    print(response["Subject"]+"\n")
    print(response)

    return response


def load():
    with open("config.yaml", 'r') as config:
        config = yaml.load(config)

        with init_gpg(config["gnupghome"]) as gpg:
            messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
            for msg in messages:
                target = msg["From"]
                response = select_response(gpg, msg)
                send_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"],
                              target, response)


if __name__ == '__main__':
    load()