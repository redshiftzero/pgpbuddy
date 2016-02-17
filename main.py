import yaml
import pdb
import time
import logging
import sys

from pgpbuddy import buddy


if __name__ == '__main__':
    logging.basicConfig(format="%(asctime)s - %(name)s: %(message)s",
                        filename="default.log", level=logging.INFO)
    log = logging.getLogger("PGPBuddy")

    screenlog = logging.StreamHandler(sys.stdout)
    screenlog.setLevel(logging.DEBUG)
    log.addHandler(screenlog)

    with open("config.yaml", 'r') as config:
        config = yaml.load(config)

    while True:
        buddy.check_and_reply_to_messages(config)
        time.sleep(60)
