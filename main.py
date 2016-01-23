import yaml
import pdb

from pgpbuddy.fetch import fetch_messages
from pgpbuddy.crypto import *
from pgpbuddy.send import send_response
from pgpbuddy.buddy import handle_message



def load():
    with open("config.yaml", 'r') as config:
        config = yaml.load(config)

        messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
        for msg in messages:
            with init_gpg(config["gnupghome"]) as gpg:
                target = msg["From"]
                response = handle_message(gpg, msg)
                send_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"],
                              target, response)


if __name__ == '__main__':
    load()