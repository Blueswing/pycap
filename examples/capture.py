from pprint import pprint

from pycap import new_ethernet_sniffer_socket
from pycap.ethernet import parse_ethernet_packet_info, unpack_ethernet_packet


# def send_ethernet():
#     sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
#     if_name = 'wlp3s0'
#     protocol = 0x0000
#     packet = struct.pack('!6s6s2s', b'\xff\xff\xff\xff\xff\xff', get_mac_address(if_name), protocol.to_bytes(2, 'big'))
#     sock.sendto(packet + b'hello', (if_name, protocol))


def main():
    sniffer = new_ethernet_sniffer_socket()
    while True:
        packet, address_info = sniffer.recvfrom(1500)
        packet_info = parse_ethernet_packet_info(address_info)
        pprint(packet_info)
        eth_header, payload = unpack_ethernet_packet(packet)
        print(eth_header, payload)
        # print('eth', packet_info, eth_header)
        # if eth_header.eth_type == 'ip':
        #     ip_header, ip_payload = parse_ipv4_packet(payload)
        #     print('ip', ip_header, ip_payload)
        #     if ip_header.protocol == 'tcp':
        #         tcp_header, tcp_payload = parse_tcp_packet(ip_payload)
        #         print('tcp', tcp_header)
        #     elif ip_header.protocol == 'icmp':
        #         print('icmp', parse_icmp_packet(ip_payload))
        # elif eth_header.eth_type == 'arp':
        #     print('arp', payload)
        # elif eth_header.eth_type == 'rarp':
        #     print('rarp', payload)
        # elif eth_header.eth_type == 'ipv6':
        #     print('ipv6', payload)
        # else:
        #     print('parser not found', eth_header.eth_type)


def demo_mac():
    print(get_interface_names())
    if_name = 'wlp3s0'
    mac = get_mac_address(if_name)
    print(mac.as_int())
    print(mac.as_bytes())
    print(mac.as_str())


if __name__ == '__main__':
    # demo_mac()
    # demo_ip()
    # send_ethernet()
    try:
        main()
    except KeyboardInterrupt:
        pass
