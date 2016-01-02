import yaml
import pdb
import re
from pgpbuddy.fetch import fetch_messages
from pgpbuddy.send import plaintext_response, encrypted_response


def form_response(msg, config):
    target = msg['From']
    regexp_enc = re.compile(r'BEGIN PGP MESSAGE')

    if regexp_enc.search(str(msg)) != None:
        encrypted_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"], target)
    elif msg['Content-Type'].split(';')[0] == 'text/plain':
        plaintext_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"], target)


def load():
    with open("config.yaml", 'r') as config:
        config = yaml.load(config)
        messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
        for msg in messages:
            form_response(msg, config)

if __name__=='__main__':
    load()
