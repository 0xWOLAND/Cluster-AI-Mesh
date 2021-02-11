

import socket
import threading
import subprocess
import os
from fcntl import ioctl
import struct


import routing_logging
import Messages
from conf import VIRT_IFACE_NAME, SET_TOPOLOGY_FLAG, GW_MODE


T_LOG = routing_logging.create_routing_log(
    "routing.transport.log", "transport")


TUNSETIFF = 0x400454ca


IFF_TUN = 0x0001


SIOCSIFADDR = 0x8916


SIOCSIFNETMASK = 0x891C


SIOCSIFMTU = 0x8922


SIOCSIFFLAGS = 0x8914


IFF_UP = 0x1


SIOCGIFINDEX = 0x8933


SIOCGIFADDR = 0x8915


IP4_ID = 0x0800


IP6_ID = 0x86DD


P_IDS = {"ICMP4": 1, "ICMP6": 58, "TCP": 6, "UDP": 17}


def get_mac(interface_name):

    try:
        string = open('/sys/class/net/%s/address' % interface_name).readline()
    except IOError:
        string = "00:00:00:00:00:00"
    return string[:17]


def get_l3_addresses_from_interface():
    def get_ipv4_address():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ipv4_addr = ioctl(s.fileno(), SIOCGIFADDR, struct.pack(
                '256s', VIRT_IFACE_NAME[:15]))[20:24]
        except IOError:

            T_LOG.debug("No IPv4 address was assigned!")
            return None

        return socket.inet_ntoa(ipv4_addr)

    def get_ipv6_address():
        ipv6_addresses = list()
        f = open("/proc/net/if_inet6", "r")
        data = f.read().split("\n")[:-1]

        for row in data:
            if row.split(" ")[-1] == VIRT_IFACE_NAME:
                ipv6_addresses.append(row.split(" ")[0])

        if ipv6_addresses:
            output = []
            for ipv6_addr in ipv6_addresses:
                ipv6_addr = ":".join([ipv6_addr[i:i + 4]
                                      for i in range(0, len(ipv6_addr), 4)])
                ipv6_addr = socket.inet_pton(socket.AF_INET6, ipv6_addr)
                output.append(socket.inet_ntop(socket.AF_INET6, ipv6_addr))
            return output
        else:

            T_LOG.debug("No IPv6 address was assigned!")

            return [None]

    addresses = list()
    addresses.append(get_ipv4_address())
    for addr in get_ipv6_address():
        addresses.append(addr)

    if GW_MODE:
        addresses.append(Messages.DEFAULT_ROUTE)

    return filter(None, addresses)


def get_l3_addresses_from_packet(packet):
    def get_data_from_ipv4_header(ipv4_packet):
        ipv4_format = "bbHHHBBHII"
        data = struct.unpack("!" + ipv4_format, ipv4_packet[4:24])
        src_ip = int2ipv4(data[-2])
        dst_ip = int2ipv4(data[-1])

        T_LOG.debug(
            "SRC and DST IPs got from the packet: %s, %s", src_ip, dst_ip)

        return [src_ip, dst_ip]

    def get_data_from_ipv6_header(ipv6_packet):
        ipv6_format = "IHBB16s16s"

        data = struct.unpack("!" + ipv6_format, ipv6_packet[4:44])

        src_ip = int2ipv6(data[-2])
        dst_ip = int2ipv6(data[-1])

        T_LOG.debug(
            "SRC and DST IPs got from the packet: %s, %s", src_ip, dst_ip)

        return [src_ip, dst_ip]

    def int2ipv4(addr):
        return socket.inet_ntoa(struct.pack("!I", addr))

    def int2ipv6(addr):
        return socket.inet_ntop(socket.AF_INET6, addr)

    l3_id = struct.unpack("!H", packet[2:4])[0]

    if l3_id == int(IP4_ID):
        addresses = get_data_from_ipv4_header(packet)
        return addresses[0], addresses[1], packet

    elif l3_id == int(IP6_ID):
        addresses = get_data_from_ipv6_header(packet)
        return addresses[0], addresses[1], packet

    elif l3_id == 0:

        return get_l3_addresses_from_packet(packet[4:])

    else:

        T_LOG.error(
            "The packet has UNSUPPORTED L3 protocol, dropping the packet")
        return None


def get_upper_proto_info(packet):
    def get_proto_id_from_ipv4(ipv4_packet):
        return struct.unpack("!B", ipv4_packet[13])[0]

    def get_proto_id_from_ipv6(ipv6_packet):
        return struct.unpack("!B", ipv6_packet[10])[0]

    def get_dst_port_from_udp(udp_upper_data):
        return struct.unpack("!H", udp_upper_data[2:4])[0]

    def get_dst_port_from_tcp(tcp_upper_data):
        return struct.unpack("!H", tcp_upper_data[2:4])[0]

    def get_src_port_from_udp(udp_upper_data):
        return struct.unpack("!H", udp_upper_data[0:2])[0]

    def get_src_port_from_tcp(tcp_upper_data):
        return struct.unpack("!H", tcp_upper_data[0:2])[0]

    l3_id = struct.unpack("!H", packet[2:4])[0]

    if l3_id == int(IP4_ID):
        proto_id = int(get_proto_id_from_ipv4(packet))

        if proto_id == P_IDS["UDP"]:

            ihl = int(struct.unpack("!B", packet[4])[0]) & 0xf
            upper_data = packet[4 + ihl * 4:]
            return "UDP", int(get_src_port_from_udp(upper_data)), int(get_dst_port_from_udp(upper_data))

        elif proto_id == P_IDS["TCP"]:

            ihl = int(struct.unpack("!B", packet[4])[0]) & 0xf
            upper_data = packet[4 + ihl * 4:]
            return "TCP", int(get_src_port_from_tcp(upper_data)), int(get_dst_port_from_tcp(upper_data))

        elif proto_id == P_IDS["ICMP4"]:

            return "ICMP4", 0, 0

        else:

            T_LOG.warning("Unknown upper protocol id: %s", proto_id)
            return "UNKNOWN", 0, 0

    elif l3_id == int(IP6_ID):
        proto_id = int(get_proto_id_from_ipv6(packet))

        if proto_id == P_IDS["UDP"]:

            ihl = 10
            upper_data = packet[4 + ihl * 4:]
            return "UDP", int(get_src_port_from_udp(upper_data)), int(get_dst_port_from_udp(upper_data))

        elif proto_id == P_IDS["TCP"]:

            ihl = 10
            upper_data = packet[4 + ihl * 4:]
            return "TCP", int(get_src_port_from_tcp(upper_data)), int(get_dst_port_from_tcp(upper_data))

        elif proto_id == P_IDS["ICMP6"]:

            return "ICMP6", 0, 0

        else:

            T_LOG.warning("Unknown upper protocol id: %s", proto_id)
            return "UNKNOWN", 0, 0

    elif l3_id == 0:

        return get_upper_proto_info(packet[4:])

    else:

        T_LOG.error(
            "The packet has UNSUPPORTED L3 protocol, dropping the packet")
        return None


class UdsClient:

    def __init__(self, server_address):

        self.server_address = server_address

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    def send(self, message):
        self.sock.sendto(message, self.server_address)


class UdsServer(threading.Thread):

    def __init__(self, server_address):
        super(UdsServer, self).__init__()

        self.running = False

        self.server_address = server_address

        self.FNULL = open(os.devnull, "w")

        subprocess.call("rm %s" % self.server_address, shell=True,
                        stdout=self.FNULL, stderr=subprocess.STDOUT)
        T_LOG.info("Deleted: %s", self.server_address)

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(self.server_address)

        self.iface = VIRT_IFACE_NAME

    def run(self):
        self.running = True
        while self.running:
            data = self.sock.recvfrom(4096)[0]
            _id, addr = data.split("-")
            if _id == "ipv4":
                self.set_ip_addr4(addr)

            elif _id == "ipv6":
                self.set_ip_addr6(addr)

            else:
                T_LOG.error(
                    "Unsupported command via UDS! This should never happen!")

    def set_ip_addr4(self, ip4):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bin_ip = socket.inet_aton(ip4)
        ifreq = struct.pack('16sH2s4s8s', self.iface,
                            socket.AF_INET, '\x00'*2, bin_ip, '\x00'*8)
        ioctl(sock, SIOCSIFADDR, ifreq)

        bin_mask = socket.inet_aton("255.255.255.0")
        ifreq = struct.pack('16sH2s4s8s', self.iface,
                            socket.AF_INET, '\x00'*2, bin_mask, '\x00'*8)
        ioctl(sock, SIOCSIFNETMASK, ifreq)

    def set_ip_addr6(self, ip6):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        bin_ipv6 = socket.inet_pton(socket.AF_INET6, ip6)
        ifreq = struct.pack('16si', self.iface, 0)
        ifreq = ioctl(sock, SIOCGIFINDEX, ifreq)
        if_index = struct.unpack("i", ifreq[16: 16 + 4])[0]
        ifreq = struct.pack('16sii', bin_ipv6, 64, if_index)
        ioctl(sock, SIOCSIFADDR, ifreq)

    def quit(self):
        self.running = False
        self.sock.close()

        subprocess.call("rm %s" % self.server_address, shell=True,
                        stdout=self.FNULL, stderr=subprocess.STDOUT)


class VirtualTransport:

    def __init__(self):

        tun_mode = IFF_TUN
        f = os.open("/dev/net/tun", os.O_RDWR)
        ioctl(f, TUNSETIFF, struct.pack("16sH", VIRT_IFACE_NAME, tun_mode))

        self.set_mtu(VIRT_IFACE_NAME, 1400)
        self.interface_up(VIRT_IFACE_NAME)

        self.f = f

        self.virtual_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.virtual_socket.bind((VIRT_IFACE_NAME, 0))

    def set_mtu(self, iface, mtu):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ifreq = struct.pack('16sI', iface, int(mtu))
        ioctl(sock, SIOCSIFMTU, ifreq)

    def interface_up(self, iface):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ifreq = struct.pack('16sH', iface, IFF_UP)
        ioctl(sock, SIOCSIFFLAGS, ifreq)

    def send_to_app(self, packet):
        os.write(self.f, packet)

    def send_to_interface(self, packet):
        self.virtual_socket.send(packet)

    def recv_from_app(self):
        output = os.read(self.f, 65000)
        return output


class RawTransport:

    def __init__(self, dev, node_mac, topology_neighbors):

        self.send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.send_socket.bind((dev, 0x7777))

        self.proto = [0x77, 0x77]

        self.node_mac = node_mac

        self.broadcast_mac = "ff:ff:ff:ff:ff:ff"

        self.topology_neighbors = topology_neighbors

        self.running = True

        self.recv_socket = self.send_socket

        if SET_TOPOLOGY_FLAG:
            self.recv_data = self.recv_data_with_filter
        else:
            self.recv_data = self.recv_data_no_filter

    def recv_data(self):
        pass

    def send_raw_frame(self, dst_mac, dsr_message, payload):
        eth_header = self.gen_eth_header(self.node_mac, dst_mac)

        dsr_bin_header = Messages.pack_message(dsr_message)
        self.send_socket.send(eth_header + dsr_bin_header + payload)

    def gen_eth_header(self, src_mac, dst_mac):
        src = [int(x, 16) for x in src_mac.split(":")]
        dst = [int(x, 16) for x in dst_mac.split(":")]
        return b"".join(map(chr, dst + src + self.proto))

    def recv_data_with_filter(self):
        while self.running:

            data = self.recv_socket.recv(65535)

            src_mac = self.get_src_mac(data[:14])

            if src_mac in self.topology_neighbors:

                T_LOG.debug(
                    "SRC_MAC from the received frame: %s", src_mac)

                dsr_header_obj, dsr_header_length = Messages.unpack_message(
                    data[14: 14 + 56])

                upper_raw_data = data[(14 + dsr_header_length):]

                return src_mac, dsr_header_obj, upper_raw_data

            elif src_mac == self.node_mac:
                T_LOG.debug(
                    "!!! THIS IS MY OWN MAC, YOBBA !!! %s", src_mac)

            else:
                T_LOG.debug(
                    "!!! THIS MAC HAS BEEN FILTERED !!! %s", src_mac)

    def recv_data_no_filter(self):
        while self.running:

            data = self.recv_socket.recv(65535)

            src_mac = self.get_src_mac(data[:14])

            if src_mac == self.node_mac:

                T_LOG.error(
                    "!!! THIS IS MY OWN MAC, YOBBA !!! %s", src_mac)

            else:

                T_LOG.debug(
                    "SRC_MAC from the received frame: %s", src_mac)

                dsr_header_obj, dsr_header_length = Messages.unpack_message(
                    data[14: 14 + 56])

                upper_raw_data = data[(14 + dsr_header_length):]

                return src_mac, dsr_header_obj, upper_raw_data

    def get_src_mac(self, eth_header):
        src_mac = ""
        data = struct.unpack("!6B", eth_header[6:12])

        for i in data:
            byte = str(hex(i))[2:]
            if len(byte) == 1:
                byte = "0" + byte
            src_mac = src_mac + byte + ":"

        return src_mac[:-1]

    def close_raw_recv_socket(self):
        self.running = False
        self.recv_socket.close()
        T_LOG.info("Raw socket closed")
