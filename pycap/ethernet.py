import struct
import subprocess
from abc import ABCMeta
from functools import lru_cache
from typing import Union, Tuple

from .base import Header
from .constants import *

ETH_TYPE_IP = 0x0800
ETH_TYPE_ARP = 0x0806
ETH_TYPE_RARP = 0x8035
ETH_TYPE_SNMP = 0x814c
ETH_TYPE_IPV6 = 0x086dd
ETH_TYPE_MPLS_UNICAST = 0x8847
ETH_TYPE_MPLS_MULTICAST = 0x8848
ETH_TYPE_PPPOE_DISCOVERY = 0x8864
ETH_TYPE_PPPOE_SESSION = 0x8864

_ETH_TYPE_MAP = {
    ETH_TYPE_IP: PROTOCOL_IP,
    ETH_TYPE_ARP: PROTOCOL_ARP,
    ETH_TYPE_RARP: PROTOCOL_RARP,
    ETH_TYPE_SNMP: PROTOCOL_SNMP,
    ETH_TYPE_IPV6: PROTOCOL_IPV6,
    ETH_TYPE_MPLS_UNICAST: PROTOCOL_MPLS,
    ETH_TYPE_MPLS_MULTICAST: PROTOCOL_MPLS,
    ETH_TYPE_PPPOE_DISCOVERY: PROTOCOL_PPPOE,
    ETH_TYPE_PPPOE_SESSION: PROTOCOL_PPPOE
}

ETH_P_ALL = 0x3  # capture all ethernet types
ETH_P_NOT_SET = 0x0  # only receive

_ETH_II_FMT = '>BBBBBBBBBBBBH'
_ETH_802_3_FMT = '>BBBBBBBBBBBBHL'

"""
This packet structure describes the pseudo-header added by Linux system.
+---------------------------+
|         Packet type       |
|         (2 Octets)        |
+---------------------------+
|        ARPHRD_ type       |
|         (2 Octets)        |
+---------------------------+
| Link-layer address length |
|         (2 Octets)        |
+---------------------------+
|    Link-layer address     |
|         (8 Octets)        |
+---------------------------+
|        Protocol type      |
|         (2 Octets)        |
+---------------------------+

The packet type field is in network byte order (big-endian); it contains a value that is one of:
    0, if the packet was specifically sent to us by somebody else;
    1, if the packet was broadcast by somebody else;
    2, if the packet was multicast, but not broadcast, by somebody else;
    3, if the packet was sent to somebody else by somebody else;
    4, if the packet was sent by us.

reference:
https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
"""
_LINK_LAYER_PACKET_TYPE_MAP = {
    0x0: 'unicast to us',
    0x1: 'boardcast to us',
    0x2: 'multicast to us',
    0x3: 'not sent to us',
    0x4: 'sent by us'
}

_interfaces = None


def get_interface_names():
    global _interfaces
    if _interfaces is None:
        import os
        _interfaces = os.listdir('/sys/class/net')
    return _interfaces


class MACAddress:

    def __init__(self, mac: Union[int, bytes, str]):
        if isinstance(mac, str):
            self._mac_s = mac
            tmp = mac.split(':')
            if len(tmp) != 6:
                raise Exception('invalid mac address')
            mac_i = 0
            for x in tmp:
                mac_i <<= 8
                mac_i += int(x, 16)
            self._mac_i = mac_i
            self._mac_b = self._mac_i.to_bytes(6, BYTE_ORDER_NET)
        elif isinstance(mac, bytes):
            self._mac_b = mac[:6]
            self._mac_i = int.from_bytes(self._mac_b, BYTE_ORDER_NET)
            self._mac_s = ':'.join('{:02x}'.format(a) for a in self._mac_b)
        else:
            self._mac_i = mac
            self._mac_b = mac.to_bytes(6, BYTE_ORDER_NET)
            self._mac_s = ':'.join('{:02x}'.format(a) for a in self._mac_b)

    def as_int(self):
        return self._mac_i

    def as_bytes(self):
        return self._mac_b

    def as_str(self):
        return self._mac_s

    def __str__(self):
        return f'MACAddress(\'{self._mac_s}\')'

    def __repr__(self):
        return self.__str__()


@lru_cache(10)
def get_mac_address(interface_name) -> MACAddress:
    res = subprocess.getoutput(f'cat /sys/class/net/{interface_name}/address')
    if len(res.split(':')) != 6:
        raise Exception('MAC address not found')
    return MACAddress(res)


def describe_eth_type(eth_type: int):
    if eth_type in _ETH_TYPE_MAP:
        return _ETH_TYPE_MAP[eth_type]
    return f'Unknown {eth_type}'


def describe_packet_type(packet_type: int):
    if packet_type in _LINK_LAYER_PACKET_TYPE_MAP:
        return _LINK_LAYER_PACKET_TYPE_MAP[packet_type]
    return f'Unknown {packet_type}'


class EthernetPacketInfo(Header):

    def __init__(self):
        self.net_if = ''
        self.protocol = 0
        self.src_mac = 0
        self.packet_type = 0
        self.address_type = 0

    def describe(self) -> dict:
        return {
            'network_interface': self.net_if,
            'protocol': describe_eth_type(self.protocol),
            'src_mac': MACAddress(self.src_mac),
            'packet_type': describe_packet_type(self.packet_type),
            'address_type': self.address_type
        }


def parse_ethernet_packet_info(raw_data):
    net_if, proto, packet_type, address_type, mac = raw_data
    obj = EthernetPacketInfo()
    obj.net_if = net_if
    obj.protocol = proto
    obj.src_mac = int.from_bytes(mac, BYTE_ORDER_NET)
    obj.packet_type = packet_type
    obj.address_type = address_type
    return obj


class EthernetHeader(Header, metaclass=ABCMeta):

    def __init__(self, dst_mac, src_mac):
        self.dst_mac = dst_mac
        self.src_mac = src_mac


class EthernetIIHeader(EthernetHeader):

    def __init__(self, dst_mac, src_mac):
        super().__init__(dst_mac, src_mac)
        self.eth_type = 0

    def describe(self) -> dict:
        return {
            'src_mac': MACAddress(self.src_mac),
            'dst_mac': MACAddress(self.dst_mac),
            'eth_type': describe_eth_type(self.eth_type)
        }


class Ethernet802_3Header(EthernetHeader):

    def __init__(self, dst_mac, src_mac):
        super().__init__(dst_mac, src_mac)
        self.length = 0
        self.llc = 0
        self.snap = 0

    def describe(self) -> dict:
        return {}


def unpack_ethernet_packet(packet) -> Tuple[Union[EthernetIIHeader, Ethernet802_3Header], bytes]:
    """
    Ethernet II header, RFC 894
        6 bytes destination MAC address
        6 bytes source MAC address
        2 bytes Ethernet type
        46 ~ 1500 bytes payload


    Ethernet 802.3 header, RFC 1042, IEEE 802
        6 bytes destination MAC address
        6 bytes source MAC address
        2 bytes length
        3 bytes LLC
        5 bytes SNAP
        38 ~ 1492 bytes payload
    """
    header, payload = packet[:14], packet[14:]
    res = struct.unpack(_ETH_II_FMT, header)
    dst_mac = int.from_bytes(res[:6], BYTE_ORDER_NET)
    src_mac = int.from_bytes(res[6:12], BYTE_ORDER_NET)
    if res[12] > 1500:
        hdr = EthernetIIHeader(dst_mac, src_mac)
        hdr.eth_type = res[12]
    else:
        hdr = Ethernet802_3Header(dst_mac, src_mac)
        # todo
    return hdr, payload
