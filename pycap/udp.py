import copy
import struct
from typing import Optional, Tuple

from .base import Header, Protocol
from .constants import PROTOCOL_DNS, PROTOCOL_MDNS, PROTOCOL_NETBIOS, PROTOCOL_SSDP

_UDP_HDR_FMT = '>HHHH'
struct_ = struct.Struct(_UDP_HDR_FMT)

_PORT_PROTOCOL_MAP = {
    53: PROTOCOL_DNS,
    5353: PROTOCOL_MDNS,
    137: PROTOCOL_NETBIOS,
    138: PROTOCOL_NETBIOS,
    139: PROTOCOL_NETBIOS,
    1900: PROTOCOL_SSDP
}


class UDPHeader(Header):

    def __init__(self, src_port: int, dst_port: int):
        self.src_port = src_port
        self.dst_port = dst_port
        self.total_length = 8
        self.checksum = 0

    def describe(self) -> dict:
        return copy.copy(self.__dict__)

    @property
    def upper_layer_protocol(self) -> Optional[str]:
        if self.src_port in _PORT_PROTOCOL_MAP:
            return _PORT_PROTOCOL_MAP[self.src_port]
        if self.dst_port in _PORT_PROTOCOL_MAP:
            return _PORT_PROTOCOL_MAP[self.dst_port]
        return f'Unknown'


class UDP(Protocol):

    def unpack_data(self, data: bytes) -> Tuple[Header, bytes]:
        p_src, p_dst, length, checksum = struct_.unpack(data[:8])
        hdr = UDPHeader(p_src, p_dst)
        hdr.total_length = length
        hdr.checksum = checksum
        return hdr, data[8:]
