__version__ = '0.1'

from .sniffer_socket import new_ethernet_sniffer_socket, new_ip_sniffer_socket

__all__ = [
    'new_ethernet_sniffer_socket',
    'new_ip_sniffer_socket'
]
