import yaml
import pdb
import re
from pgpbuddy.fetch import fetch_messages
from pgpbuddy.send import (plaintext_response, encrypted_response,
                           signed_response, encryptsigned_response)


def form_response(msg, config):
    target = msg['From']
    regexp_enc = re.compile(r'BEGIN PGP MESSAGE')
    regexp_sig = re.compile(r'BEGIN PGP SIGNED')

    if regexp_enc.search(str(msg)) is not None:
        encrypted_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"], target)
        decrypted_response = msg  ## decrypt here TODO
        if regexp_sig.search(str(decrypted_response)) is not None:
            ## check valid sig TODO
            encryptsigned_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"], target)
    elif regexp_sig.search(str(msg)) is not None:
        ## check valid sig TODO
        signed_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"], target)
    elif msg['Content-Type'].split(';')[0] == 'text/plain':
        plaintext_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"], target)

    return None


def load():
    with open("config.yaml", 'r') as config:
        config = yaml.load(config)
        messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
        for msg in messages:
            form_response(msg, config)

    return None

if __name__=='__main__':
    load()