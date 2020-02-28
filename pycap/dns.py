import copy
import struct
from typing import Tuple, Any

from .base import Header, Protocol, DataObject, NotSupportedError

"""

References:
    https://tools.ietf.org/html/rfc1035
"""
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

_Q_TYPE_MAP = {
    1: 'A',
    2: 'NS',
    3: 'NS',
    4: 'MF',
    5: 'CNAME',
    6: 'SOA',
    7: 'MB',
    8: 'MG',
    9: 'MR',
    10: 'NULL',
    11: 'WKS',
    12: 'PTR',
    13: 'HINFO',
    14: 'MINFO',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    252: 'AXFR',
    253: 'MAILB',
    254: 'MALA',
    255: 'ANY'
}

_Q_CLASS_MAP = {
    1: 'IN',  # Internet
    2: 'CS',  # CSNET
    3: 'CH',  # CHAOS
    4: 'HS',  # Hesiod
    255: 'ANY'
}


def describe_q_type(typ: int):
    if typ in _Q_TYPE_MAP:
        return _Q_TYPE_MAP[typ]
    return f'Unknown {typ}'


def describe_q_class(kls: int):
    if kls in _Q_CLASS_MAP:
        return _Q_CLASS_MAP[kls]
    return f'Unknown {kls}'


class DNSHeader(Header):
    def __init__(self):
        self.identifier = 0
        self.qr = 0
        self.opcode = 0
        self.authoritative_answer = 0
        self.truncation = 0
        self.recursion_desired = 0
        self.recursion_available = 0
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


class DNSQuery(DataObject):

    def __init__(self):
        self.q_name = ''
        self.q_type = 0
        self.q_class = 0

    def describe(self) -> dict:
        return {

        }


class DNSResourceRecord(DataObject):

    def __init__(self):
        pass

    def describe(self) -> dict:
        pass


def _parse_domain_name(data: bytes):
    idx = 0
    domain_lst = []
    while True:
        length = data[idx]
        idx += 1
        if length == 0:
            break
        domain_lst.append(data[idx:idx + length].decode())
        idx += length
    return '.'.join(domain_lst), idx


class DNS(Protocol):

    def unpack_data(self, data: bytes) -> Tuple[Header, Any]:
        identifier, id2, question, answer, auth, addition = _STRUCT_DNS_FIXED_HDR.unpack(data[:12])
        hdr = DNSHeader()
        hdr.identifier = identifier
        hdr.response_code = id2 & 0xf
        id2 >>= 4
        hdr.z = id2 & 0x7
        id2 >>= 3
        hdr.recursion_available = id2 & 0x1
        id2 >>= 1
        hdr.recursion_desired = id2 & 0x1
        id2 >>= 1
        hdr.truncation = id2 & 0x1
        id2 >>= 1
        hdr.authoritative_answer = id2 & 0x1
        id2 >>= 1
        hdr.opcode = id2 & 0xf
        id2 >>= 4
        hdr.qr = id2 & 0x1
        hdr.question_count = question
        hdr.answer_count = answer
        hdr.authority = auth
        hdr.additional_info = addition
        raw_payload = data[12:]
        payload_list = []
        idx = 0
        for _ in range(hdr.question_count):
            qry = DNSQuery()
            name, length = _parse_domain_name(raw_payload)
            qry.q_name = name
            idx += length
            qry.q_type, qry.q_class = struct.unpack('>HH', raw_payload[idx:idx + 4])
            payload_list.append(qry)
            idx += 4

        for _ in range(hdr.answer_count):
            payload = DNSResourceRecord()
            if raw_payload[idx] >> 6 != 3:
                raise NotSupportedError(raw_payload[idx])
            offset, payload.r_type, payload.r_class, \
                payload.ttl, payload.rd_length = struct.unpack('>HHHIH', raw_payload[idx:idx + 12])
            offset &= 0x3fff
            name, _ = _parse_domain_name(data[offset:])
            idx += 12
            payload.name = name
            payload.r_data = raw_payload[idx:idx + payload.rd_length]
            idx += payload.rd_length
            payload_list.append(payload)
        return hdr, payload_list
