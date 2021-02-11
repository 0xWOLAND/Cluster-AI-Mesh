

from random import randint
from socket import AF_INET6, inet_pton, inet_aton, inet_ntoa, inet_ntop
from socket import error as sock_error
from math import ceil
import ctypes
import struct
import binascii


DEFAULT_ROUTE = "0.0.0.0"


DEFAULT_IPV6 = "fe80::"


def pack_message(message):
    if isinstance(message, UnicastPacket):
        return UnicastHeader().pack(message)

    elif isinstance(message, BroadcastPacket):
        return BroadcastHeader().pack(message)

    elif isinstance(message, RreqMessage):

        try:
            inet_aton(message.src_ip)
            message.type = 2
            return Rreq4Header().pack(message)

        except sock_error:
            message.type = 3
            return Rreq6Header().pack(message)

    elif isinstance(message, RrepMessage):

        try:
            inet_aton(message.src_ip)
            message.type = 4
            return Rrep4Header().pack(message)

        except sock_error:
            message.type = 5
            return Rrep6Header().pack(message)

    elif isinstance(message, HelloMessage):
        return HelloHeader().pack(message)

    elif isinstance(message, AckMessage):
        return AckHeader().pack(message)

    elif isinstance(message, RewardMessage):
        return RewardHeader().pack(message)

    elif isinstance(message, ReliableDataPacket):
        return ReliableDataHeader().pack(message)

    else:
        return None


def unpack_message(binary_header):
    class TypeField(ctypes.LittleEndianStructure):
        _fields_ = [
            ("TYPE", ctypes.c_uint32, 4),
        ]

    type_binary_field = binary_header[:4]
    type_field_unpacked = TypeField.from_buffer_copy(type_binary_field)
    type_value = type_field_unpacked.TYPE

    if type_value == 0:
        return UnicastHeader().unpack(binary_header)

    elif type_value == 1:
        return BroadcastHeader().unpack(binary_header)

    elif type_value == 2:
        return Rreq4Header().unpack(binary_header)

    elif type_value == 3:
        return Rreq6Header().unpack(binary_header)

    elif type_value == 4:
        return Rrep4Header().unpack(binary_header)

    elif type_value == 5:
        return Rrep6Header().unpack(binary_header)

    elif type_value == 6:
        return HelloHeader().unpack(binary_header)

    elif type_value == 7:
        return AckHeader().unpack(binary_header)

    elif type_value == 8:
        return RewardHeader().unpack(binary_header)

    elif type_value == 9:
        return ReliableDataHeader().unpack(binary_header)

    else:
        return None


class UnicastPacket:

    type = 0

    def __init__(self):

        self.id = randint(0, 1048575)

        self.hop_count = 0

    def __str__(self):
        out_tuple = (self.type, self.id, self.hop_count)
        out_string = "TYPE: %s, ID: %s, HOP_COUNT: %s" % out_tuple
        return out_string


class BroadcastPacket:

    type = 1

    def __init__(self):

        self.id = self.id = randint(0, 1048575)

        self.broadcast_ttl = 0

    def __str__(self):
        out_tuple = (self.type, self.id, self.broadcast_ttl)
        out_string = "TYPE: %s, ID: %s, BROADCAST_TTL: %s" % out_tuple
        return out_string


class RreqMessage:

    type = int()

    def __init__(self):

        self.id = randint(0, 1048575)

        self.src_ip = str()

        self.dst_ip = str()

        self.hop_count = 0

    def __str__(self):
        out_tuple = (self.id, self.src_ip, self.dst_ip, self.hop_count)
        out_string = "ID: %s, SRC_IP: %s, DST_IP: %s, HOP_COUNT: %s" % out_tuple
        return out_string


class RrepMessage:

    type = int()

    def __init__(self):

        self.id = randint(0, 1048575)

        self.src_ip = str()

        self.dst_ip = str()

        self.hop_count = 0

    def __str__(self):
        out_tuple = (self.type, self.id, self.src_ip,
                     self.dst_ip, self.hop_count)
        out_string = "TYPE: %s, ID: %s, SRC_IP: %s, DST_IP: %s, HOP_COUNT: %s" % out_tuple
        return out_string


class HelloMessage:

    type = 6

    def __init__(self):

        self.ipv4_count = 0

        self.ipv6_count = 0

        self.ipv4_address = str()

        self.ipv6_addresses = list()

        self.tx_count = 0

        self.gw_mode = 0

    def __str__(self):
        out_tuple = (self.type, self.ipv4_address,
                     self.ipv6_addresses, self.tx_count, self.gw_mode)
        out_string = "TYPE: %s, IPV4_ADDRESS: %s, IPV6_ADDRESSES: %s, TX_COUNT: %s, GW_MODE: %s" % out_tuple
        return out_string


class AckMessage:

    type = 7

    def __init__(self):

        self.id = randint(0, 1048575)

        self.tx_count = 0

        self.msg_hash = 0

    def __str__(self):
        out_tuple = (self.type, self.id, self.tx_count, self.msg_hash)
        out_string = "TYPE: %s, ID: %s, TX_COUNT: %s, MSG_HASH: %s" % out_tuple
        return out_string


class RewardMessage:

    type = 8

    def __init__(self, reward_value, msg_hash):

        self.id = randint(0, 1048575)

        self.reward_value = int(ceil(reward_value))

        self.msg_hash = msg_hash

    def __str__(self):
        out_tuple = (self.type, self.id, self.reward_value, self.msg_hash)
        out_string = "TYPE: %s, ID: %s, REWARD_VALUE: %s, MSG_HASH: %s" % out_tuple
        return out_string


class ReliableDataPacket:

    type = 9

    def __init__(self):

        self.id = randint(0, 1048575)

        self.hop_count = 0

    def __str__(self):
        out_tuple = (self.type, self.id, self.hop_count)
        out_string = "TYPE: %s, ID: %s, HOP_COUNT: %s" % out_tuple
        return out_string


class UnicastHeader:

    class Header(ctypes.LittleEndianStructure):
        _fields_ = [
            ("TYPE", ctypes.c_uint32, 4),
            ("ID", ctypes.c_uint32, 20),
            ("HOP_COUNT", ctypes.c_uint32, 8)
        ]

    def __init__(self):
        pass

    def pack(self, unicast_message):
        header = self.Header(unicast_message.type,
                             unicast_message.id, unicast_message.hop_count)

        return bytearray(header)

    def unpack(self, binary_header):

        header_unpacked = self.Header.from_buffer_copy(binary_header)

        message = UnicastPacket()
        message.id = header_unpacked.ID
        message.hop_count = header_unpacked.HOP_COUNT

        return message, len(bytearray(header_unpacked))


class BroadcastHeader:

    class Header(ctypes.LittleEndianStructure):
        _fields_ = [
            ("TYPE", ctypes.c_uint32, 4),
            ("ID", ctypes.c_uint32, 20),
            ("BROADCAST_TTL", ctypes.c_uint32, 8)
        ]

    def __init__(self):
        pass

    def pack(self, broadcast_message):
        header = self.Header(
            broadcast_message.type, broadcast_message.id, broadcast_message.broadcast_ttl)

        return bytearray(header)

    def unpack(self, binary_header):

        header_unpacked = self.Header.from_buffer_copy(binary_header)

        message = BroadcastPacket()
        message.id = header_unpacked.ID
        message.broadcast_ttl = header_unpacked.BROADCAST_TTL

        return message, len(bytearray(header_unpacked))


class Rreq4Header:

    class Header(ctypes.LittleEndianStructure):
        _fields_ = [
            ("TYPE", ctypes.c_uint32, 4),
            ("ID", ctypes.c_uint32, 20),
            ("HOP_COUNT", ctypes.c_uint32, 8),
            ("SRC_IP", ctypes.c_uint32, 32),
            ("DST_IP", ctypes.c_uint32, 32)
        ]

    def __init__(self):
        pass

    def pack(self, rreq4_message):

        src_ip = struct.unpack("!I", inet_aton(rreq4_message.src_ip))[0]
        dst_ip = struct.unpack("!I", inet_aton(rreq4_message.dst_ip))[0]
        header = self.Header(rreq4_message.type, rreq4_message.id,
                             rreq4_message.hop_count, src_ip, dst_ip)

        return bytearray(header)

    def unpack(self, binary_header):

        header_unpacked = self.Header.from_buffer_copy(binary_header)

        message = RreqMessage()
        message.type = header_unpacked.TYPE
        message.id = header_unpacked.ID
        message.hop_count = header_unpacked.HOP_COUNT
        message.src_ip = inet_ntoa(struct.pack("!I", header_unpacked.SRC_IP))
        message.dst_ip = inet_ntoa(struct.pack("!I", header_unpacked.DST_IP))

        return message, len(bytearray(header_unpacked))


class Rreq6Header:

    class Header(ctypes.LittleEndianStructure):
        _fields_ = [
            ("TYPE", ctypes.c_uint32, 4),
            ("ID", ctypes.c_uint32, 20),
            ("HOP_COUNT", ctypes.c_uint32, 8),
            ("SRC_IP1", ctypes.c_uint32, 32),
            ("SRC_IP2", ctypes.c_uint32, 32),
            ("SRC_IP3", ctypes.c_uint32, 32),
            ("SRC_IP4", ctypes.c_uint32, 32),
            ("DST_IP1", ctypes.c_uint32, 32),
            ("DST_IP2", ctypes.c_uint32, 32),
            ("DST_IP3", ctypes.c_uint32, 32),
            ("DST_IP4", ctypes.c_uint32, 32)
        ]

    max_int64 = 0xFFFFFFFFFFFFFFFF

    max_int32 = 0xFFFFFFFF

    def __init__(self):
        pass

    def pack(self, rreq6_message):

        src_ip = int(binascii.hexlify(
            inet_pton(AF_INET6, rreq6_message.src_ip)), 16)

        if rreq6_message.dst_ip == DEFAULT_ROUTE:
            rreq6_message.dst_ip = DEFAULT_IPV6

        dst_ip = int(binascii.hexlify(
            inet_pton(AF_INET6, rreq6_message.dst_ip)), 16)

        src_ip_left_64 = (src_ip >> 64) & self.max_int64
        src_ip_right_64 = src_ip & self.max_int64
        dst_ip_left_64 = (dst_ip >> 64) & self.max_int64
        dst_ip_right_64 = dst_ip & self.max_int64

        header = self.Header(rreq6_message.type, rreq6_message.id, rreq6_message.hop_count,
                             (src_ip_left_64 >>
                              32) & self.max_int32, src_ip_left_64 & self.max_int32,
                             (src_ip_right_64 >>
                              32) & self.max_int32, src_ip_right_64 & self.max_int32,
                             (dst_ip_left_64 >>
                              32) & self.max_int32, dst_ip_left_64 & self.max_int32,
                             (dst_ip_right_64 >> 32) & self.max_int32, dst_ip_right_64 & self.max_int32)

        return bytearray(header)

    def unpack(self, binary_header):

        header_unpacked = self.Header.from_buffer_copy(binary_header)

        message = RreqMessage()
        message.type = header_unpacked.TYPE
        message.id = header_unpacked.ID
        message.hop_count = header_unpacked.HOP_COUNT

        src_ip_left_64 = (header_unpacked.SRC_IP1 <<
                          32 | header_unpacked.SRC_IP2)
        src_ip_right_64 = (header_unpacked.SRC_IP3 <<
                           32 | header_unpacked.SRC_IP4)
        dst_ip_left_64 = (header_unpacked.DST_IP1 <<
                          32 | header_unpacked.DST_IP2)
        dst_ip_right_64 = (header_unpacked.DST_IP3 <<
                           32 | header_unpacked.DST_IP4)

        src_ip_packed_value = struct.pack(
            b"!QQ", src_ip_left_64, src_ip_right_64)
        dst_ip_packed_value = struct.pack(
            b"!QQ", dst_ip_left_64, dst_ip_right_64)

        message.src_ip = inet_ntop(AF_INET6, src_ip_packed_value)
        message.dst_ip = inet_ntop(AF_INET6, dst_ip_packed_value)

        if message.dst_ip == DEFAULT_IPV6:
            message.dst_ip = DEFAULT_ROUTE

        return message, len(bytearray(header_unpacked))


class Rrep4Header:

    class Header(ctypes.LittleEndianStructure):
        _fields_ = [
            ("TYPE", ctypes.c_uint32, 4),
            ("ID", ctypes.c_uint32, 20),
            ("HOP_COUNT", ctypes.c_uint32, 8),
            ("SRC_IP", ctypes.c_uint32, 32),
            ("DST_IP", ctypes.c_uint32, 32)
        ]

    def __init__(self):
        pass

    def pack(self, rrep4_message):

        src_ip = struct.unpack("!I", inet_aton(rrep4_message.src_ip))[0]
        dst_ip = struct.unpack("!I", inet_aton(rrep4_message.dst_ip))[0]
        header = self.Header(rrep4_message.type, rrep4_message.id,
                             rrep4_message.hop_count, src_ip, dst_ip)

        return bytearray(header)

    def unpack(self, binary_header):

        header_unpacked = self.Header.from_buffer_copy(binary_header)

        message = RrepMessage()
        message.type = header_unpacked.TYPE
        message.id = header_unpacked.ID
        message.hop_count = header_unpacked.HOP_COUNT
        message.src_ip = inet_ntoa(struct.pack("!I", header_unpacked.SRC_IP))
        message.dst_ip = inet_ntoa(struct.pack("!I", header_unpacked.DST_IP))

        return message, len(bytearray(header_unpacked))


class Rrep6Header:

    class Header(ctypes.LittleEndianStructure):
        _fields_ = [
            ("TYPE", ctypes.c_uint32, 4),
            ("ID", ctypes.c_uint32, 20),
            ("HOP_COUNT", ctypes.c_uint32, 8),
            ("SRC_IP1", ctypes.c_uint32, 32),
            ("SRC_IP2", ctypes.c_uint32, 32),
            ("SRC_IP3", ctypes.c_uint32, 32),
            ("SRC_IP4", ctypes.c_uint32, 32),
            ("DST_IP1", ctypes.c_uint32, 32),
            ("DST_IP2", ctypes.c_uint32, 32),
            ("DST_IP3", ctypes.c_uint32, 32),
            ("DST_IP4", ctypes.c_uint32, 32)
        ]

    max_int64 = 0xFFFFFFFFFFFFFFFF

    max_int32 = 0xFFFFFFFF

    def __init__(self):
        pass

    def pack(self, rrep6_message):

        if rrep6_message.src_ip == DEFAULT_ROUTE:
            rrep6_message.src_ip = DEFAULT_IPV6

        src_ip = int(binascii.hexlify(
            inet_pton(AF_INET6, rrep6_message.src_ip)), 16)
        dst_ip = int(binascii.hexlify(
            inet_pton(AF_INET6, rrep6_message.dst_ip)), 16)

        src_ip_left_64 = (src_ip >> 64) & self.max_int64
        src_ip_right_64 = src_ip & self.max_int64
        dst_ip_left_64 = (dst_ip >> 64) & self.max_int64
        dst_ip_right_64 = dst_ip & self.max_int64

        header = self.Header(rrep6_message.type, rrep6_message.id, rrep6_message.hop_count,
                             (src_ip_left_64 >>
                              32) & self.max_int32, src_ip_left_64 & self.max_int32,
                             (src_ip_right_64 >>
                              32) & self.max_int32, src_ip_right_64 & self.max_int32,
                             (dst_ip_left_64 >>
                              32) & self.max_int32, dst_ip_left_64 & self.max_int32,
                             (dst_ip_right_64 >> 32) & self.max_int32, dst_ip_right_64 & self.max_int32)

        return bytearray(header)

    def unpack(self, binary_header):

        header_unpacked = self.Header.from_buffer_copy(binary_header)

        message = RrepMessage()
        message.type = header_unpacked.TYPE
        message.id = header_unpacked.ID
        message.hop_count = header_unpacked.HOP_COUNT

        src_ip_left_64 = (header_unpacked.SRC_IP1 <<
                          32 | header_unpacked.SRC_IP2)
        src_ip_right_64 = (header_unpacked.SRC_IP3 <<
                           32 | header_unpacked.SRC_IP4)
        dst_ip_left_64 = (header_unpacked.DST_IP1 <<
                          32 | header_unpacked.DST_IP2)
        dst_ip_right_64 = (header_unpacked.DST_IP3 <<
                           32 | header_unpacked.DST_IP4)

        src_ip_packed_value = struct.pack(
            b"!QQ", src_ip_left_64, src_ip_right_64)
        dst_ip_packed_value = struct.pack(
            b"!QQ", dst_ip_left_64, dst_ip_right_64)

        message.src_ip = inet_ntop(AF_INET6, src_ip_packed_value)
        message.dst_ip = inet_ntop(AF_INET6, dst_ip_packed_value)

        if message.src_ip == DEFAULT_IPV6:
            message.src_ip = DEFAULT_ROUTE

        return message, len(bytearray(header_unpacked))


class HelloHeader:

    class FixedHeader(ctypes.LittleEndianStructure):
        _fields_ = [("TYPE", ctypes.c_uint32, 4),
                    ("IPV4_COUNT", ctypes.c_uint32, 1),
                    ("IPV6_COUNT", ctypes.c_uint32, 2),
                    ("TX_COUNT", ctypes.c_uint32, 24),
                    ("GW_MODE", ctypes.c_uint32, 1)
                    ]

    class OnlyIpv4Header(ctypes.LittleEndianStructure):
        _fields_ = [("TYPE", ctypes.c_uint32, 4),
                    ("IPV4_COUNT", ctypes.c_uint32, 1),
                    ("IPV6_COUNT", ctypes.c_uint32, 2),
                    ("TX_COUNT", ctypes.c_uint32, 24),
                    ("GW_MODE", ctypes.c_uint32, 1),
                    ("IPV4_ADDRESS", ctypes.c_uint32, 32)
                    ]

    max_int64 = 0xFFFFFFFFFFFFFFFF

    max_int32 = 0xFFFFFFFF

    def __init__(self):
        pass

    def pack(self, hello_message):
        args = [hello_message.type, hello_message.ipv4_count, hello_message.ipv6_count,
                hello_message.tx_count, hello_message.gw_mode]

        if hello_message.ipv4_count and hello_message.ipv6_count == 0:
            ipv4_address = struct.unpack(
                "!I", inet_aton(hello_message.ipv4_address))[0]
            args.append(ipv4_address)
            header = self.OnlyIpv4Header(*args)

        elif hello_message.ipv6_count:
            fields = list(self.FixedHeader._fields_)
            if hello_message.ipv4_count:
                fields.append(("IPV4_ADDRESS", ctypes.c_uint32, 32))
                ipv4_address = struct.unpack(
                    "!I", inet_aton(hello_message.ipv4_address))[0]
                args.append(ipv4_address)

            for i in xrange(hello_message.ipv6_count):
                fields.append(("IPV6_ADDRESS_%s_1" % i, ctypes.c_uint32, 32))
                fields.append(("IPV6_ADDRESS_%s_2" % i, ctypes.c_uint32, 32))
                fields.append(("IPV6_ADDRESS_%s_3" % i, ctypes.c_uint32, 32))
                fields.append(("IPV6_ADDRESS_%s_4" % i, ctypes.c_uint32, 32))

                ipv6_address = int(binascii.hexlify(
                    inet_pton(AF_INET6, hello_message.ipv6_addresses[i])), 16)
                ipv6_address_left = (ipv6_address >> 64) & self.max_int64
                ipv6_address_right = ipv6_address & self.max_int64

                args.extend([(ipv6_address_left >> 32) & self.max_int32, ipv6_address_left & self.max_int32,
                             (ipv6_address_right >> 32) & self.max_int32, ipv6_address_right & self.max_int32])

            class Header(ctypes.Structure):
                _fields_ = fields

            header = Header(*args)

        else:
            header = self.FixedHeader(*args)

        return bytearray(header)

    def unpack(self, binary_header):

        fixed_header_unpacked = self.FixedHeader.from_buffer_copy(
            binary_header)

        message = HelloMessage()

        if fixed_header_unpacked.IPV4_COUNT and fixed_header_unpacked.IPV6_COUNT == 0:
            header_unpacked = self.OnlyIpv4Header.from_buffer_copy(
                binary_header)
            message.ipv4_address = inet_ntoa(
                struct.pack("!I", header_unpacked.IPV4_ADDRESS))

        elif fixed_header_unpacked.IPV6_COUNT:

            fields = list(self.FixedHeader._fields_)
            if fixed_header_unpacked.IPV4_COUNT:
                fields.append(("IPV4_ADDRESS", ctypes.c_uint32, 32))

            for i in xrange(fixed_header_unpacked.IPV6_COUNT):
                fields.append(("IPV6_ADDRESS_%s_1" % i, ctypes.c_uint32, 32))
                fields.append(("IPV6_ADDRESS_%s_2" % i, ctypes.c_uint32, 32))
                fields.append(("IPV6_ADDRESS_%s_3" % i, ctypes.c_uint32, 32))
                fields.append(("IPV6_ADDRESS_%s_4" % i, ctypes.c_uint32, 32))

            class Header(ctypes.Structure):
                _fields_ = fields

            header_unpacked = Header.from_buffer_copy(binary_header)

            if header_unpacked.IPV4_COUNT:
                message.ipv4_address = inet_ntoa(
                    struct.pack("!I", header_unpacked.IPV4_ADDRESS))

            for i in xrange(header_unpacked.IPV6_COUNT):

                ipv6_left = (getattr(header_unpacked, "IPV6_ADDRESS_%s_1" % i) << 32 |
                             getattr(header_unpacked, "IPV6_ADDRESS_%s_2" % i))
                ipv6_right = (getattr(header_unpacked, "IPV6_ADDRESS_%s_3" % i) << 32 |
                              getattr(header_unpacked, "IPV6_ADDRESS_%s_4" % i))

                ipv6_packed_value = struct.pack(b"!QQ", ipv6_left, ipv6_right)

                message.ipv6_addresses.append(
                    inet_ntop(AF_INET6, ipv6_packed_value))

        else:
            message.tx_count = fixed_header_unpacked.TX_COUNT
            message.gw_mode = fixed_header_unpacked.GW_MODE
            message.ipv4_count = fixed_header_unpacked.IPV4_COUNT
            message.ipv6_count = fixed_header_unpacked.IPV6_COUNT

            return message, len(bytearray(fixed_header_unpacked))

        message.ipv4_count = header_unpacked.IPV4_COUNT
        message.ipv6_count = header_unpacked.IPV6_COUNT
        message.tx_count = header_unpacked.TX_COUNT
        message.gw_mode = header_unpacked.GW_MODE

        return message, len(bytearray(header_unpacked))


class AckHeader:

    class Header(ctypes.LittleEndianStructure):
        _fields_ = [
            ("TYPE", ctypes.c_uint32, 4),
            ("ID", ctypes.c_uint32, 20),
            ("TX_COUNT", ctypes.c_uint32, 8),
            ("MSG_HASH", ctypes.c_uint32, 32)
        ]

    def __init__(self):
        pass

    def pack(self, ack_message):
        header = self.Header(ack_message.type, ack_message.id,
                             ack_message.tx_count, ack_message.msg_hash)

        return bytearray(header)

    def unpack(self, binary_header):

        header_unpacked = self.Header.from_buffer_copy(binary_header)

        message = AckMessage()
        message.id = header_unpacked.ID
        message.tx_count = header_unpacked.TX_COUNT
        message.msg_hash = header_unpacked.MSG_HASH

        return message, len(bytearray(header_unpacked))


class RewardHeader:

    class Header(ctypes.LittleEndianStructure):
        _fields_ = [
            ("TYPE", ctypes.c_uint32, 4),
            ("ID", ctypes.c_uint32, 20),
            ("NEG_REWARD_FLAG", ctypes.c_uint32, 1),
            ("REWARD_VALUE", ctypes.c_uint32, 7),
            ("MSG_HASH", ctypes.c_uint32, 32)
        ]

    def __init__(self):
        pass

    def pack(self, reward_message):
        if reward_message.reward_value < 0:
            header = self.Header(reward_message.type, reward_message.id, 1,
                                 abs(reward_message.reward_value), reward_message.msg_hash)
        else:
            header = self.Header(reward_message.type, reward_message.id, 0,
                                 reward_message.reward_value, reward_message.msg_hash)

        return bytearray(header)

    def unpack(self, binary_header):

        header_unpacked = self.Header.from_buffer_copy(binary_header)
        if header_unpacked.NEG_REWARD_FLAG:
            message = RewardMessage(-1 * header_unpacked.REWARD_VALUE,
                                    header_unpacked.MSG_HASH)
            message.id = header_unpacked.ID
        else:
            message = RewardMessage(
                header_unpacked.REWARD_VALUE, header_unpacked.MSG_HASH)
            message.id = header_unpacked.ID

        return message, len(bytearray(header_unpacked))


class ReliableDataHeader:

    class Header(ctypes.LittleEndianStructure):
        _fields_ = [
            ("TYPE", ctypes.c_uint32, 4),
            ("ID", ctypes.c_uint32, 20),
            ("HOP_COUNT", ctypes.c_uint32, 8)
        ]

    def __init__(self):
        pass

    def pack(self, reliable_data_packet):
        header = self.Header(reliable_data_packet.type,
                             reliable_data_packet.id, reliable_data_packet.hop_count)

        return bytearray(header)

    def unpack(self, binary_header):

        header_unpacked = self.Header.from_buffer_copy(binary_header)

        message = ReliableDataPacket()
        message.id = header_unpacked.ID
        message.hop_count = header_unpacked.HOP_COUNT

        return message, len(bytearray(header_unpacked))
