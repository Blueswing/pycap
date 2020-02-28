import copy
import ipaddress
import socket
import struct
from typing import Tuple, Optional

from .base import Header, Protocol
from .constants import *

"""
Internet header format

    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


References:
    https://www.rfc-editor.org/rfc/rfc791.txt
"""
IPv4Address = ipaddress.IPv4Address
IPv6Address = ipaddress.IPv6Address

_IP_HEADER_FMT = '>BBHHHBBHII'

_PROTO_MAP = {
    1: PROTOCOL_ICMP,
    2: PROTOCOL_IGMP,
    6: PROTOCOL_TCP,
    17: PROTOCOL_UDP,
    89: PROTOCOL_OSPF
}


def describe_protocol(proto):
    if proto in _PROTO_MAP:
        return _PROTO_MAP[proto]
    return f'Unknown {proto}'


def get_local_ip_address():
    return IPv4Address(socket.gethostbyname(socket.gethostname()))


def get_ip_address(host):
    return IPv4Address(socket.gethostbyname(host))


class IPv4Header(Header):

    def __init__(self, src_ip, dst_ip):
        self.version = 4
        self.header_len = 20
        self.tos = 0
        self.total_len = 20
        self.id_frag = 0
        self.df = 1
        self.mf = 0
        self.offset = 0
        self.ttl = 255
        self.protocol = 0
        self.checksum = 0
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.options = b''

    @property
    def upper_layer_protocol(self) -> Optional[str]:
        return describe_protocol(self.protocol)

    def describe(self) -> dict:
        dct = copy.copy(self.__dict__)
        dct['src_ip'] = IPv4Address(self.src_ip)
        dct['dst_ip'] = IPv4Address(self.dst_ip)
        dct['protocol'] = describe_protocol(self.protocol)
        return dct


class IPv6Header(Header):
    def __init__(self, src_ip, dst_ip):
        self.version = 6
        self.header_len = 0
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def describe(self) -> dict:
        return copy.copy(self.__dict__)


class IP(Protocol):

    def unpack_data(self, data: bytes) -> Tuple[Header, bytes]:
        """
        4 bit   version
        4 bit   header length in 4 bytes
        8 bit   type of service
        16 bit  total length
        16 bit  identification, used to differentiate packets from different datagrams
        3 bit   flags, used to control fragments;
                    1st. bit is not used, must be zero
                    2nd. bit: DF, 0 = may fragment, 1 = don't fragment
                    3rd. bit: MF, 0 = last fragment, 1 = more fragments
        13 bit  offsest in 8 bytes
        8 bit   ttl
        8 bit   protocol, the upper layer protocol
        16 bit  checksum
        32 bit  source IP address
        32 bit  destination IP address
        N bit   options
        N bit   padding
        N bit   payload data
        """
        byte_0 = data[0]
        version = byte_0 >> 4
        if version != 4:
            raise ValueError(version)
        res = struct.unpack(_IP_HEADER_FMT, data[:20])
        header = IPv4Header(res[8], res[9])
        header.version = version
        header.header_len = (byte_0 & 0xf) * 4  # bytes
        header.tos = res[1]
        header.total_len = res[2]  # bytes
        header.id_frag = res[3]
        ident_3 = res[4] >> 13
        header.df = (ident_3 >> 1) & 0x1
        header.mf = ident_3 & 0x1
        header.offset = (res[4] & 0x1fff) * 8  # bytes
        header.ttl = res[5]
        header.protocol = res[6]
        header.checksum = res[7]
        opt_len = header.header_len - 20
        if opt_len:
            header.options = data[20:20 + opt_len]
        payload = data[header.header_len:header.total_len]
        return header, payload


class IPv6(Protocol):

    def unpack_data(self, data: bytes) -> Tuple[Header, bytes]:
        byte_0 = data[0]
        version = byte_0 >> 4
        if version != 6:
            raise ValueError(version)
        # todo
        return IPv6Header(0, 0), b''
