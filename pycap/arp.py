import struct
from typing import Tuple

from .base import Header, Protocol, NotSupportedError
from .constants import BYTE_ORDER_NET
from .ethernet import ETH_TYPE_IP, MACAddress, describe_eth_type, ETH_TYPE_IPV6
from .ip import IPv4Address, IPv6Address

_FMT_ARP_FIXED_HDR = '>HHBBH'
_STRUCT_ARP_FIXED_HDR = struct.Struct(_FMT_ARP_FIXED_HDR)
_LEN_ARP_FIXED_HDR = _STRUCT_ARP_FIXED_HDR.size

_MAP_HARDWARE_TYPE = {1: 'Ethernet'}

_MAP_OPCODE = {1: 'request', 2: 'reply'}


def describe_hardware_type(hardware_type: int):
    if hardware_type in _MAP_HARDWARE_TYPE:
        return _MAP_HARDWARE_TYPE[hardware_type]
    return f'Unknown {hardware_type}'


def describe_opcode(opcode: int):
    if opcode in _MAP_OPCODE:
        return _MAP_OPCODE[opcode]
    return f'Unknown {opcode}'


class ARPHeader(Header):

    def __init__(self):
        self.hardware_type = 0
        self.protocol = 0
        self.hardware_addr_len = 0
        self.protocol_addr_len = 0
        self.opcode = 0
        self.src_hardware_addr = 0
        self.src_protocol_addr = 0
        self.dst_hardware_addr = 0
        self.dst_protocol_addr = 0

    def describe(self):
        dct = {
            'hardware_type': describe_hardware_type(self.hardware_type),
            'protocol': describe_eth_type(self.protocol),
            'hardware_addr_len': self.hardware_addr_len,
            'protocol_addr_len': self.protocol_addr_len,
            'opcode': describe_opcode(self.opcode)}
        if self.protocol == ETH_TYPE_IP:
            dct['src_hardware_addr'] = MACAddress(self.src_hardware_addr)
            dct['src_protocol_addr'] = IPv4Address(self.src_protocol_addr)
            dct['dst_hardware_addr'] = MACAddress(self.dst_hardware_addr)
            dct['dst_protocol_addr'] = IPv4Address(self.dst_protocol_addr)
            return dct
        if self.protocol == ETH_TYPE_IPV6:
            dct['src_hardware_addr'] = MACAddress(self.src_hardware_addr)
            dct['src_protocol_addr'] = IPv6Address(self.src_protocol_addr)
            dct['dst_hardware_addr'] = MACAddress(self.dst_hardware_addr)
            dct['dst_protocol_addr'] = IPv6Address(self.dst_protocol_addr)
            return dct
        raise NotSupportedError(self.protocol)


class ARP(Protocol):

    def unpack_data(self, data: bytes) -> Tuple[Header, bytes]:
        """
        ARP packet format

        16 bits hardware address space
        16 bits protocol address space
        8 bits  length of hardware address
        8 bits  length of protocol address
        16 bits opcode, request or reply
        n bits  hardware address of sender
        m bits  protocol address of sender
        n bits  hardware address of receiver
        m bits  protocol address of receiver
        x bits  padding
        """
        hdr = ARPHeader()
        hdr.hardware_type, hdr.protocol, hdr.hardware_addr_len, hdr.protocol_addr_len, hdr.opcode = \
            _STRUCT_ARP_FIXED_HDR.unpack(data[:_LEN_ARP_FIXED_HDR])
        packet = data[_LEN_ARP_FIXED_HDR:]
        idx_end = hdr.hardware_addr_len
        hdr.src_hardware_addr = int.from_bytes(packet[:idx_end], BYTE_ORDER_NET)
        idx_start = idx_end
        idx_end += hdr.protocol_addr_len
        hdr.src_protocol_addr = int.from_bytes(packet[idx_start:idx_start], BYTE_ORDER_NET)
        idx_start = idx_end
        idx_end += hdr.hardware_addr_len
        hdr.dst_hardware_addr = int.from_bytes(packet[idx_start:idx_end], BYTE_ORDER_NET)
        idx_start = idx_end
        idx_end += hdr.protocol_addr_len
        hdr.dst_protocol_addr = int.from_bytes(packet[idx_start:idx_end], BYTE_ORDER_NET)
        return hdr, packet[idx_end:]
