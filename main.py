import yaml
import pdb
import time

from pgpbuddy import buddy


if __name__ == '__main__':
    with open("config.yaml", 'r') as config:
        config = yaml.load(config)

    while True:
        buddy.check_and_reply_to_messages(config)
        time.sleep(60)
