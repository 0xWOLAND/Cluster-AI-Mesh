

import threading
import hashlib
import time


import Messages
import routing_logging


lock = threading.Lock()


ARQ_HANDLER_LOG = routing_logging.create_routing_log(
    "routing.arq_handler.log", "arq_handler")


max_int32 = 0xFFFFFFFF


class ArqHandler:

    def __init__(self, raw_transport, table):

        self.msg_thread_map = {}

        self.raw_transport = raw_transport

        self.table = table

    def arq_send(self, message, dest_mac_list, payload=""):
        for dst_address in dest_mac_list:
            ARQ_HANDLER_LOG.debug("ARQ_SEND for %s", dst_address)

            hash_str = hashlib.md5(str(message.id) + dst_address).hexdigest()

            hash_int = int(hash_str, 16) & max_int32

            lock.acquire()
            self.msg_thread_map[hash_int] = ArqRoutine(hash_int, self.msg_thread_map, self.raw_transport,
                                                       message, payload, dst_address)
            lock.release()
            self.msg_thread_map[hash_int].start()

    def arq_broadcast_send(self, message, payload=""):
        dest_mac_list = self.table.get_neighbors()
        for dst_address in dest_mac_list:
            ARQ_HANDLER_LOG.debug("ARQ_SEND for %s", dst_address)

            hash_str = hashlib.md5(str(message.id) + dst_address).hexdigest()

            hash_int = int(hash_str, 16) & max_int32

            lock.acquire()
            self.msg_thread_map[hash_int] = ArqRoutine(hash_int, self.msg_thread_map, self.raw_transport,
                                                       message, payload, dst_address)
            lock.release()
            self.msg_thread_map[hash_int].start()

    def process_ack(self, ack_message):
        hash_int = ack_message.msg_hash

        if hash_int in self.msg_thread_map:

            self.msg_thread_map[hash_int].quit()

            lock.acquire()
            if self.msg_thread_map.get(hash_int):
                del self.msg_thread_map[hash_int]
            lock.release()
        else:

            ARQ_HANDLER_LOG.info("No such ACK with this hash!!! Do nothing...")

    def send_ack(self, message, dst_mac):
        ARQ_HANDLER_LOG.info(
            "Sending ACK back on the message %s", str(message))

        hash_str = hashlib.md5(
            str(message.id) + self.raw_transport.node_mac).hexdigest()

        hash_int = int(hash_str, 16) & max_int32

        ack_message = Messages.AckMessage()
        ack_message.msg_hash = hash_int

        self.raw_transport.send_raw_frame(dst_mac, ack_message, "")


class ArqRoutine(threading.Thread):

    def __init__(self, hash_int, msg_thread_map, raw_transport, message, payload, dst_address):
        super(ArqRoutine, self).__init__()

        self.running = False

        self.hash_int = hash_int

        self.msg_thread_map = msg_thread_map

        self.raw_transport = raw_transport

        self.dsr_message = message

        self.payload = payload

        self.dst_address = dst_address

        self.max_retries = 5

        self.timeout_interval = 0.5

    def run(self):
        self.running = True
        count = 0
        while self.running:
            if count < self.max_retries:
                self.send_msg()
                time.sleep(self.timeout_interval)
            else:

                ARQ_HANDLER_LOG.info(
                    "Maximum ARQ retries reached!!! Deleting the ARQ thread...")
                lock.acquire()
                if self.msg_thread_map.get(self.hash_int):
                    del self.msg_thread_map[self.hash_int]
                lock.release()

                self.quit()

            count += 1

    def send_msg(self):
        self.raw_transport.send_raw_frame(
            self.dst_address, self.dsr_message, self.payload)
        ARQ_HANDLER_LOG.debug("Sent raw frame on: %s", self.dst_address)

    def quit(self):
        self.running = False
