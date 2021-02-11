

import os
import threading
import Queue
import logging
from logging.handlers import RotatingFileHandler


from conf import LOG_LEVEL


ABSOLUTE_PATH = os.path.dirname(os.path.abspath(__file__))


PATH_TO_LOGS = "/var/log/adhoc_routing/"


LOG_QUEUE = Queue.Queue()


if LOG_LEVEL == "CRITICAL":
    LOG_LEVEL = logging.CRITICAL
elif LOG_LEVEL == "ERROR":
    LOG_LEVEL = logging.ERROR
elif LOG_LEVEL == "WARNING":
    LOG_LEVEL = logging.WARNING
elif LOG_LEVEL == "INFO":
    LOG_LEVEL = logging.INFO
elif LOG_LEVEL == "DEBUG":
    LOG_LEVEL = logging.DEBUG
else:

    LOG_LEVEL = logging.INFO


class LoggingHandler(threading.Thread):

    def __init__(self):
        super(LoggingHandler, self).__init__()

        self.running = False

        self.root_logger = logging.getLogger()

    def run(self):
        self.running = True
        self.root_logger.info("STARTING THE LOG THREAD...")
        while self.running:

            log_object_method, msg, args, kwargs = LOG_QUEUE.get()

            log_object_method(msg, *args, **kwargs)

    def quit(self):
        self.running = False
        self.root_logger.info("STOPPING THE LOG THREAD...")


class LogWrapper:

    def __init__(self, logger_object):

        self.logger_object = logger_object
        self.info("THE LOG INSTANCE IS CREATED: %s", self.logger_object.name)

    def info(self, msg, *args, **kwargs):
        LOG_QUEUE.put((self.logger_object.info, msg, args, kwargs))

    def debug(self, msg, *args, **kwargs):
        LOG_QUEUE.put((self.logger_object.debug, msg, args, kwargs))

    def error(self, msg, *args, **kwargs):
        LOG_QUEUE.put((self.logger_object.error, msg, args, kwargs))

    def warning(self, msg, *args, **kwargs):
        LOG_QUEUE.put((self.logger_object.warning, msg, args, kwargs))

    def critical(self, msg, *args, **kwargs):
        LOG_QUEUE.put((self.logger_object.critical, msg, args, kwargs))


def create_routing_log(log_name, log_hierarchy):

    if not os.path.exists(PATH_TO_LOGS):
        os.makedirs(PATH_TO_LOGS)

    log_formatter = logging.Formatter(
        '%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
    log_file = PATH_TO_LOGS + log_name
    log_handler = RotatingFileHandler(log_file, mode='a', maxBytes=5*1024*1024,
                                      backupCount=10, encoding=None, delay=0)

    log_handler.setFormatter(log_formatter)
    log_handler.setLevel(LOG_LEVEL)

    if log_hierarchy == "root":
        routing_log = logging.getLogger()
    else:
        routing_log = logging.getLogger(log_hierarchy)

    if routing_log.handlers:

        log_wrapper_object = LogWrapper(routing_log)
        return log_wrapper_object

    routing_log.setLevel(LOG_LEVEL)
    routing_log.addHandler(log_handler)

    log_wrapper_object = LogWrapper(routing_log)
    return log_wrapper_object


def init_log_thread():
    global LOG_THREAD
    LOG_THREAD = LoggingHandler()
    LOG_THREAD.start()


def stop_log_thread():
    LOG_THREAD.quit()
