import yaml
import pdb
from pgpbuddy.fetch import fetch_messages
from pgpbuddy.send import (plaintext_response, encrypted_response,
                           signed_response, encryptsigned_response)
from pgpbuddy.crypto import init_gpg, is_encrypted, is_signed, decrypt, verify_signature, import_public_key


def select_response(gpg, msg):
    if is_encrypted(msg):
        decrypted_message = decrypt(gpg, msg)

        if is_signed(decrypted_message):
            ## check valid sig TODO
            return encryptsigned_response
        else:
            return encrypted_response

    elif is_signed(msg):
        import_public_key(gpg, msg["From"])
        verify_signature(gpg, msg)
        return signed_response

    elif msg['Content-Type'].split(';')[0] == 'text/plain':
        return plaintext_response

    return None


def load():
    with open("config.yaml", 'r') as config:
        config = yaml.load(config)
        with init_gpg(config["gnupghome"]) as gpg:
            messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
            for msg in messages:
                target = msg["From"]
                respond = select_response(gpg, msg)
                #respond(config["smtp-server"], config["smtp-port"], config["username"], config["password"], target)

    return None

if __name__=='__main__':
    load()