import yaml
from pgpbuddy.fetch import fetch_messages

with open("config.yaml", 'r') as config:
    config = yaml.load(config)
    messages = fetch_messages(config["pop3-server"], config["username"], config["password"])
    for msg in messages:
        print(msg)