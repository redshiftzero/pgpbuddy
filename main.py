import yaml
import pdb

from pgpbuddy import buddy


if __name__ == '__main__':
    with open("config.yaml", 'r') as config:
        config = yaml.load(config)
        buddy.check_and_reply_to_messages(config)