import yaml
import pdb
from pgpbuddy.fetch import fetch_messages
from pgpbuddy.send import send_response, get_message
from pgpbuddy.crytpo import init_gpg, is_encrypted, is_signed, decrypt_message


def select_response(gpg, msg):
    if is_encrypted(msg):
        decrypted_message = decrypt_message(gpg, msg)

        if is_signed(decrypted_message):
            ## check valid sig TODO
            return get_message('encrypted_signed')
        else:
            return get_message('encrypted_success')

    elif is_signed(msg):
        ## check valid sig TODO
        return get_message('signed_success')

    else:
        return get_message('plaintext')

    return None


def load():
    with open("config.yaml", 'r') as config:
        config = yaml.load(config)
        gpg = init_gpg(config["gnupghome"])

        messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
        for msg in messages:
            target = msg["From"]
            response = select_response(gpg, msg)
            send_response(config["smtp-server"], config["smtp-port"], config["username"], config["password"], target, response)

    return None

if __name__=='__main__':
    load()