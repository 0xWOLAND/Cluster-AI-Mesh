

import time


import Messages
import routing_logging


PATH_DISCOVERY_LOG = routing_logging.create_routing_log(
    "routing.path_discovery.log", "path_discovery")


class PathDiscoveryHandler:

    def __init__(self, app_transport, arq_handler):

        self.delayed_packets_list = {}

        self.entry_deletion_timeout = 3

        self.creation_timestamps = {}

        self.failed_ips = set([])

        self.app_transport = app_transport

        self.arq_handler = arq_handler

    def run_path_discovery(self, src_ip, dst_ip, packet):

        if dst_ip in self.delayed_packets_list:

            if (time.time() - self.creation_timestamps[dst_ip]) > self.entry_deletion_timeout:

                self.delayed_packets_list.pop(dst_ip, None)

                self.creation_timestamps.pop(dst_ip, None)

                self.failed_ips.add(dst_ip)

                self.run_path_discovery(src_ip, dst_ip, packet)

            else:

                self.delayed_packets_list[dst_ip].append(packet)
                PATH_DISCOVERY_LOG.info("Added a delayed packet: %s", dst_ip)

        else:
            PATH_DISCOVERY_LOG.info("No DST_IP in rreq list: %s", dst_ip)

            self.delayed_packets_list.update({dst_ip: [packet]})

            self.creation_timestamps.update({dst_ip: time.time()})

            self.send_rreq(src_ip, dst_ip)

    def send_rreq(self, src_ip, dst_ip):
        rreq = Messages.RreqMessage()
        rreq.src_ip = src_ip
        rreq.dst_ip = dst_ip
        rreq.hop_count = 1

        self.arq_handler.arq_broadcast_send(rreq)
        PATH_DISCOVERY_LOG.info(
            "New  RREQ for IP: '%s' has been sent. Waiting for RREP", dst_ip)

    def process_rrep(self, rrep):
        src_ip = rrep.src_ip
        PATH_DISCOVERY_LOG.info("Got RREP. Deleting RREQ thread...")

        if src_ip in self.delayed_packets_list:
            packets = list(self.delayed_packets_list[src_ip])

            for packet in packets:
                PATH_DISCOVERY_LOG.info(
                    "Putting delayed packets back to app_queue...")
                PATH_DISCOVERY_LOG.debug("Packet dst_ip: %s", src_ip)
                self.app_transport.send_to_interface(packet)

            self.delayed_packets_list.pop(src_ip, None)

            self.creation_timestamps.pop(src_ip, None)

            self.failed_ips.discard(src_ip)
