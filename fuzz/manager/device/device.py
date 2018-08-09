import logging
import sys
import logging.handlers

# represents a fuzzing target
class Device:
    def __init__(self, relay, ip, username="user", password="password", name="unnamed"):
        # configure logger
        logger = logging.getLogger("%s.%s" % (__name__, relay))

        file_handler = logging.handlers.RotatingFileHandler('device_%d.log' % relay, maxBytes=0, backupCount=50)
        file_handler.doRollover()
        logger.addHandler(file_handler)

        stream_handler = logging.StreamHandler(sys.stdout)
        logger.addHandler(stream_handler)

        logger.setLevel(logging.INFO)

        # configure device
        self.relay = relay
        self.ip = ip
        self.up = False
        self.username = username
        self.password = password
        self.name = name
        self.logger = logger

    def dprint(self, *args):
        m = "> device <%d, %s, %s>: " % (self.relay, self.ip, self.name) + " ".join(map(str, args))
        self.logger.info(m)
