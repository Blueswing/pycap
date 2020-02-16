import ipaddress
import socket
import struct
from typing import Tuple, Union

from .base import DataObject
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
_IP_HEADER_FMT = '>BBHHHBBHII'

_PROTO_MAP = {
    1: PROTOCOL_ICMP,
    2: PROTOCOL_IGMP,
    6: PROTOCOL_TCP,
    17: PROTOCOL_UDP,
    89: PROTOCOL_OSPF
}


def get_local_ip_address():
    return ipaddress.IPv4Address(socket.gethostbyname(socket.gethostname()))


def get_ip_address(host):
    return ipaddress.IPv4Address(socket.gethostbyname(host))


class IPv4Header(DataObject):

    def __init__(self):
        self.version = None
        self.header_len = None
        self.tos = None
        self.total_len = None
        self.id_frag = None
        self.df = None
        self.mf = None
        self.offset = None
        self.ttl = None
        self.protocol = None
        self.checksum = None
        self.src_ip = None
        self.dst_ip = None
        self.options = b''


class IPv6Header:
    pass


def unpack_ip_packet(data: bytes) -> Tuple[Union[IPv4Header, IPv6Header], bytes]:
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
    if version == 4:
        header = IPv4Header()
        res = struct.unpack(_IP_HEADER_FMT, data[:20])
        header.version = version
        header.header_len = (byte_0 & 0xf) * 4  # bytes
        header.tos = res[1]
        header.total_len = res[2]  # bytes
        header.id_frag = res[3]
        ident_3 = res[4] >> 13
        header.df = bool((ident_3 >> 1) & 0x1)
        header.mf = bool(ident_3 & 0x1)
        header.offset = (res[4] & 0x1fff) * 8  # bytes
        header.ttl = res[5]
        header.protocol = _PROTO_MAP[res[6]]
        header.checksum = res[7]
        header.src_ip = ipaddress.IPv4Address(res[8])
        header.dst_ip = ipaddress.IPv4Address(res[9])
        opt_len = header.header_len - 20
        if opt_len:
            header.options = data[20:20 + opt_len]
        payload = data[header.header_len:header.total_len]
        return header, payload
    elif version == 6:
        # todo
        return IPv6Header(), b''
    else:
        raise ValueError(version)
