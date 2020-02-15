import struct
from typing import Tuple

from .base import DataObject

_TCP_HDR_FMT = '>HHIIHHHH'
struct_ = struct.Struct(_TCP_HDR_FMT)


class TCPHeader(DataObject):

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_id = 0
        self.ack_id = 0
        self.header_len = 0
        self.urg = False
        self.ack = False
        self.psh = False
        self.rst = False
        self.syn = False
        self.fin = False
        self.window_size = 0
        self.checksum = 0
        self.offset = 0


def unpack_tcp_packet(data: bytes) -> Tuple[TCPHeader, bytes]:
    header = TCPHeader()
    header.src_port, header.dst_port, header.seq_id, header.ack_id, \
        tmp, header.window_size, header.checksum, header.offset = \
        struct_.unpack(data[:struct_.size])

    header.fin = bool(tmp & 0x1)
    tmp >>= 1
    header.syn = bool(tmp & 0x1)
    tmp >>= 1
    header.rst = bool(tmp & 0x1)
    tmp >>= 1
    header.psh = bool(tmp & 0x1)
    tmp >>= 1
    header.ack = bool(tmp & 0x1)
    tmp >>= 1
    header.urg = bool(tmp & 0x1)
    header.header_len = 4 * (tmp >> 7)
    return header, data[struct_.size:]
