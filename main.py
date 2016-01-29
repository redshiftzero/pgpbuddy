import yaml
import pdb
import schedule
import time

from pgpbuddy import buddy


if __name__ == '__main__':
    with open("config.yaml", 'r') as config:
        config = yaml.load(config)

    schedule.every(1).minutes.do(buddy.check_and_reply_to_messages(config))
    while True:
        schedule.run_pending()
        time.sleep(20)
