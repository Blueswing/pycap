import copy
import struct
from typing import Tuple

from .base import Header, Protocol

_FMT_DNS_FIXED_HDR = '>HHHHHH'
_STRUCT_DNS_FIXED_HDR = struct.Struct(_FMT_DNS_FIXED_HDR)
_QR_MAP = {0: 'query', 1: 'response'}
_OPCODE_MAP = {
    0: 'QUERY',
    1: 'IQUERY',
    2: 'STATUS'
}
_RCODE_MAP = {
    0: 'No error condition',
    1: 'Format error',
    2: 'Server failure',
    3: 'Name error',
    4: 'Not Implemented',
    5: 'Refused'
}


class DNSHeader(Header):
    def __init__(self):
        self.identifier = 0
        self.qr = 0
        self.opcode = 0
        self.authoritative_answer = False
        self.truncation = False
        self.recursion_desired = False
        self.recursion_available = False
        self.z = 0
        self.response_code = 0
        self.question_count = 0
        self.answer_count = 0
        self.authority = 0
        self.additional_info = 0

    def describe(self) -> dict:
        dct = copy.copy(self.__dict__)
        dct['qr'] = _QR_MAP[self.qr]
        dct['opcode'] = _OPCODE_MAP.get(self.opcode, 'reserved')
        return dct


class DNS(Protocol):

    def unpack_data(self, data: bytes) -> Tuple[Header, bytes]:
        identifier, id2, question, answer, auth, addition = _STRUCT_DNS_FIXED_HDR.unpack(data[:12])
        hdr = DNSHeader()
        hdr.identifier = identifier
        hdr.response_code = id2 & 0xf
        id2 >>= 4
        hdr.z = id2 & 0x7
        id2 >>= 3
        hdr.recursion_available = bool(id2 & 0x1)
        id2 >>= 1
        hdr.recursion_desired = bool(id2 & 0x1)
        id2 >>= 1
        hdr.truncation = bool(id2 & 0x1)
        id2 >>= 1
        hdr.authoritative_answer = bool(id2 & 0x1)
        id2 >>= 1
        hdr.opcode = id2 & 0xf
        id2 >>= 4
        hdr.qr = id2 & 0x1
        hdr.question_count = question
        hdr.answer_count = answer
        hdr.authority = auth
        hdr.additional_info = addition
        return hdr, data[12:]
