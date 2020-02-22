import struct
import copy
from typing import Tuple

from .base import Header, Protocol

_ICMP_RESPONSE_FMT = '>BBHHH'


class ICMPHeader(Header):

    def __init__(self):
        self.icmp_type = 0
        self.code = 0
        self.checksum = 0
        self.identifier = 0
        self.seq_number = 0

    def describe(self) -> dict:
        return copy.copy(self.__dict__)


class ICMP(Protocol):

    def unpack_data(self, data: bytes) -> Tuple[Header, bytes]:
        _type, code, checksum, identifier, seq_number = \
            struct.unpack(_ICMP_RESPONSE_FMT, data[:8])
        header = ICMPHeader()
        header.icmp_type = _type
        header.code = code
        header.checksum = checksum
        header.identifier = identifier
        header.seq_number = seq_number
        return header, data[8:]
