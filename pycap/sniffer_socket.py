import socket

from .ethernet import ETH_P_ALL, ETH_TYPE_IP


def new_ethernet_sniffer_socket(protocol=ETH_P_ALL):
    return socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(protocol))


def new_ip_sniffer_socket():
    return socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_TYPE_IP))
