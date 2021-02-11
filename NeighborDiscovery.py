

import Messages
import Transport
import threading
import time
from socket import inet_aton
from socket import error as sock_error


import routing_logging


PATH_TO_LOGS = routing_logging.PATH_TO_LOGS


NEIGHBOR_LOG = routing_logging.create_routing_log(
    "routing.neighbor_discovery.log", "neighbor_discovery")


class Neighbor:

    def __init__(self):

        self.l3_addresses = list()

        self.mac = str()

        self.last_activity = time.time()


class NeighborDiscovery:

    def __init__(self, raw_transport_obj, table_obj):

        f = open(PATH_TO_LOGS + "neighbors_file", "w")
        f.close()

        self.listen_neighbors_handler = ListenNeighbors(
            raw_transport_obj.node_mac, table_obj)

        self.advertise_thread = AdvertiseNeighbor(raw_transport_obj, table_obj)

    def run(self):
        self.advertise_thread.start()

    def stop_threads(self):
        self.advertise_thread.quit()
        NEIGHBOR_LOG.info("NeighborDiscovery threads are stopped")


class AdvertiseNeighbor(threading.Thread):

    def __init__(self, raw_transport_obj, table_obj):
        super(AdvertiseNeighbor, self).__init__()

        self.running = False

        self.current_node_ips = [None]

        self.message = Messages.HelloMessage()

        self.broadcast_mac = raw_transport_obj.broadcast_mac

        self.broadcast_interval = 2

        self.raw_transport = raw_transport_obj

        self.table_obj = table_obj

        self.node_mac = raw_transport_obj.node_mac

    def run(self):
        self.running = True
        while self.running:

            self.send_raw_hello()

            self.table_obj.print_table()
            time.sleep(self.broadcast_interval)

    def update_ips_in_route_table(self, node_ips):
        for ip in node_ips:
            if ip not in self.table_obj.current_node_ips:
                self.table_obj.update_entry(ip, self.node_mac, 100)
        self.table_obj.current_node_ips = node_ips

    def send_raw_hello(self):

        node_ips = Transport.get_l3_addresses_from_interface()

        if self.current_node_ips != node_ips:

            self.update_ips_in_route_table(node_ips)

            if Messages.DEFAULT_ROUTE in node_ips:
                self.message.gw_mode = 1
                ips = node_ips[:-1]

            else:
                self.message.gw_mode = 0
                ips = node_ips

            if ips:

                try:
                    inet_aton(ips[0])
                    self.message.ipv4_count = 1
                    self.message.ipv4_address = ips[0]

                    self.message.ipv6_count = len(ips[1:])
                    self.message.ipv6_addresses = ips[1:]

                except sock_error:

                    self.message.ipv4_count = 0
                    self.message.ipv6_count = len(ips)
                    self.message.ipv6_addresses = ips

            else:
                self.message.ipv4_count = 0
                self.message.ipv6_count = 0

        NEIGHBOR_LOG.debug("Sending HELLO message:\n %s", self.message)

        self.raw_transport.send_raw_frame(self.broadcast_mac, self.message, "")
        self.message.tx_count += 1

        self.current_node_ips = node_ips

    def quit(self):
        self.running = False


class ListenNeighbors:

    def __init__(self, node_mac, table_obj):

        self.node_mac = node_mac

        self.table = table_obj

        self.neighbors_list = table_obj.neighbors_list

        self.expiry_interval = 7

        self.last_expiry_check = time.time()

    def process_neighbor(self, src_mac, dsr_hello_message):
        l3_addresses_from_message = []
        if dsr_hello_message.ipv4_count:
            l3_addresses_from_message.append(dsr_hello_message.ipv4_address)

        if dsr_hello_message.ipv6_count:
            for ipv6 in dsr_hello_message.ipv6_addresses:
                l3_addresses_from_message.append(ipv6)

        if dsr_hello_message.gw_mode == 1:
            l3_addresses_from_message.append(Messages.DEFAULT_ROUTE)

        if (time.time() - self.last_expiry_check) > self.expiry_interval:
            self.check_expired_neighbors()
            self.last_expiry_check = time.time()

        if src_mac == self.node_mac:
            NEIGHBOR_LOG.warning(
                "Neighbor has the same mac address as mine! %s", self.node_mac)
            return False

        if src_mac not in self.neighbors_list:
            neighbor = Neighbor()

            neighbor.l3_addresses = l3_addresses_from_message
            neighbor.mac = src_mac

            self.neighbors_list[src_mac] = neighbor

            self.add_neighbor_entry(neighbor)

            for ip in neighbor.l3_addresses:
                self.table.update_entry(ip, src_mac, 50)

        else:
            if self.neighbors_list[src_mac].l3_addresses != l3_addresses_from_message:
                self.neighbors_list[src_mac].l3_addresses = l3_addresses_from_message

                for ip in l3_addresses_from_message:
                    self.table.update_entry(ip, src_mac, 50)

            self.neighbors_list[src_mac].last_activity = time.time()

        self.update_neighbors_file()

    def update_neighbors_file(self):
        f = open(PATH_TO_LOGS + "neighbors_file", "w")
        for mac in self.neighbors_list:

            NEIGHBOR_LOG.debug("Neighbor's IPs: %s", str(
                self.neighbors_list[mac].l3_addresses))

            for addr in self.neighbors_list[mac].l3_addresses:
                if addr:
                    f.write(addr)
                    f.write("\n")
            f.write("\n")
        f.close()

    def check_expired_neighbors(self):
        macs_to_delete = []
        for n in self.neighbors_list:
            if (time.time() - self.neighbors_list[n].last_activity) > self.expiry_interval:
                macs_to_delete.append(n)

        for mac in macs_to_delete:

            NEIGHBOR_LOG.info(
                "Neighbor has gone offline. Removing: %s", str(mac))

            self.del_neighbor_entry(mac)

    def add_neighbor_entry(self, neighbor):
        NEIGHBOR_LOG.info("Adding a new neighbor: %s", str(neighbor.mac))
        self.neighbors_list.update({neighbor.mac: neighbor})

    def del_neighbor_entry(self, mac):
        NEIGHBOR_LOG.debug("Deleting the neighbor: %s", str(mac))
        if mac in self.neighbors_list:
            del self.neighbors_list[mac]
