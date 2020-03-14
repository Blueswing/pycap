import os
import socket
from .base import NotSupportedError
from .ethernet import ETH_P_ALL, ETH_TYPE_IP


def get_local_ip_address():
    return socket.gethostbyname(socket.gethostname())


def new_ethernet_sniffer_socket(protocol=ETH_P_ALL):
    if os.name == 'nt':
        raise NotSupportedError('Windows is not supported.')
    return socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(protocol))


def new_ip_sniffer_socket():
    if os.name == 'nt':
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((get_local_ip_address(), 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return s
    else:
        return socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_TYPE_IP))
