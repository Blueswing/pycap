import socket
import struct

from network.ethernet import parse_ethernet_packet, parse_ethernet_packet_info, ETH_P_ALL, get_mac_address, \
    get_interface_names
from network.icmp import parse_icmp_packet
from network.ip import parse_ipv4_packet
from network.ping import ping
from network.tcp import parse_tcp_packet


def send_ethernet():
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    if_name = 'wlp3s0'
    protocol = 0x0000
    packet = struct.pack('!6s6s2s', b'\xff\xff\xff\xff\xff\xff', get_mac_address(if_name), protocol.to_bytes(2, 'big'))
    sock.sendto(packet + b'hello', (if_name, protocol))


def main():
    sniffer = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    while True:
        packet, address_info = sniffer.recvfrom(1500)
        packet_info = parse_ethernet_packet_info(address_info)
        # pprint(packet_info)
        eth_header, payload = parse_ethernet_packet(packet)
        # print('eth', packet_info, eth_header)
        if eth_header.eth_type == 'ip':
            ip_header, ip_payload = parse_ipv4_packet(payload)
            print('ip', ip_header, ip_payload)
            if ip_header.protocol == 'tcp':
                tcp_header, tcp_payload = parse_tcp_packet(ip_payload)
                print('tcp', tcp_header)
            elif ip_header.protocol == 'icmp':
                print('icmp', parse_icmp_packet(ip_payload))
        elif eth_header.eth_type == 'arp':
            print('arp', payload)
        elif eth_header.eth_type == 'rarp':
            print('rarp', payload)
        elif eth_header.eth_type == 'ipv6':
            print('ipv6', payload)
        else:
            print('parser not found', eth_header.eth_type)


def demo_mac():
    print(get_interface_names())
    if_name = 'wlp3s0'
    mac = get_mac_address(if_name)
    print(mac.as_int())
    print(mac.as_bytes())
    print(mac.as_str())


def demo_ip():
    from network.ip import get_ip_address, get_local_ip_address
    print(get_ip_address('www.baidu.com'))
    print(get_ip_address('www.yeefea.com'))
    print(get_ip_address('huiyin.yeefea.com'))
    print(get_local_ip_address())


if __name__ == '__main__':
    # demo_mac()
    # demo_ip()
    # send_ethernet()
    try:
        # main()
        ping('www.baidu.com')
    except KeyboardInterrupt:
        pass
