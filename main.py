import yaml
import pdb
from pgpbuddy.fetch import fetch_messages
from pgpbuddy.send import send_message

with open("config.yaml", 'r') as config:
    config = yaml.load(config)
    messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
    for msg in messages:
        target = msg['From'].split()[1].strip('<>')

        if msg['Content-Type'].split(';')[0] == 'text/plain':
            send_message(config["smtp-server"], config["smtp-port"], config["username"], config["password"], target)
