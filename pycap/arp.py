import struct

from .base import DataObject, BYTE_ORDER

_FMT_ARP_FIXED_HDR = '>HHBBH'
_STRUCT_ARP_FIXED_HDR = struct.Struct(_FMT_ARP_FIXED_HDR)
_LEN_ARP_FIXED_HDR = _STRUCT_ARP_FIXED_HDR.size

_MAP_HARDWARE_TYPE = {
    1: 'Ethernet'
}


def describe_hardware_type(hardware_type: int):
    if hardware_type in _MAP_HARDWARE_TYPE:
        return _MAP_HARDWARE_TYPE[hardware_type]
    return f'Unknown {hardware_type}'


class ARPHeader(DataObject):

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
        return {
            'hardware_type': describe_hardware_type(self.hardware_type),
            'protocol': self.protocol,
            'hardware_addr_len': self.hardware_addr_len,
            'protocol_addr_len': self.protocol_addr_len,
            'opcode': self.opcode,
        }


def unpack_arp_packet(packet: bytes):
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
    hdr.hardware_type, hdr.protocol, hdr.hardware_addr_len, hdr.protocol_addr_len, hdr.opcode = _STRUCT_ARP_FIXED_HDR.unpack(
        packet[:_LEN_ARP_FIXED_HDR])
    packet = packet[_LEN_ARP_FIXED_HDR:]
    idx_end = hdr.hardware_addr_len
    hdr.src_hardware_addr = int.from_bytes(packet[:idx_end], BYTE_ORDER)
    idx_start = idx_end
    idx_end += hdr.protocol_addr_len
    hdr.src_protocol_addr = int.from_bytes(packet[idx_start:idx_start], BYTE_ORDER)
    idx_start = idx_end
    idx_end += hdr.hardware_addr_len
    hdr.dst_hardware_addr = int.from_bytes(packet[idx_start:idx_end], BYTE_ORDER)
    idx_start = idx_end
    idx_end += hdr.protocol_addr_len
    hdr.dst_protocol_addr = int.from_bytes(packet[idx_start:idx_end], BYTE_ORDER)
    return hdr, packet[idx_end:]
