import struct

from .base import DataObject

_ICMP_RESPONSE_FMT = '>BBHHH'


class ICMPHeader(DataObject):
    def __init__(self):
        self.icmp_type = 0
        self.code = 0
        self.checksum = 0
        self.identifier = 0
        self.seq_number = 0


def parse_icmp_packet(data: bytes):
    _type, code, checksum, identifier, seq_number = struct.unpack(
        _ICMP_RESPONSE_FMT, data[:8])
    header = ICMPHeader()
    header.icmp_type = _type
    header.code = code
    header.checksum = checksum
    header.identifier = identifier
    header.seq_number = seq_number
    return header, data[8:]
