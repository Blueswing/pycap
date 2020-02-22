from pycap import new_ethernet_sniffer_socket
from pycap.arp import unpack_arp_packet
from pycap.constants import PROTOCOL_ETH, PROTOCOL_IP, PROTOCOL_TCP, PROTOCOL_ARP, PROTOCOL_RARP, PROTOCOL_IPV6, \
    PROTOCOL_ICMP
from pycap.ethernet import parse_ethernet_packet_info, unpack_ethernet_packet
from pycap.icmp import unpack_icmp_packet
from pycap.ip import unpack_ip_packet
from pycap.tcp import unpack_tcp_packet


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
        print('info', packet_info.describe())
        eth_header, payload = unpack_ethernet_packet(packet)
        print(PROTOCOL_ETH, eth_header.describe())
        if eth_header.upper_layer_protocol == PROTOCOL_IP:
            ip_header, ip_payload = unpack_ip_packet(payload)
            print('  ', PROTOCOL_IP, ip_header.describe())
            if ip_header.upper_layer_protocol == PROTOCOL_TCP:
                tcp_header, tcp_payload = unpack_tcp_packet(ip_payload)
                print('    ', PROTOCOL_TCP, tcp_header.describe(), tcp_payload)
            elif ip_header.upper_layer_protocol == PROTOCOL_ICMP:
                icmp_header, icmp_payload = unpack_icmp_packet(ip_payload)
                print('    ', PROTOCOL_ICMP, icmp_header.describe(), icmp_payload)
        elif eth_header.upper_layer_protocol == PROTOCOL_ARP:
            hdr, arp_payload = unpack_arp_packet(payload)
            print('  ', PROTOCOL_ARP, hdr.describe(), arp_payload)
        elif eth_header.upper_layer_protocol == PROTOCOL_RARP:
            print('  ', PROTOCOL_RARP, payload)
        elif eth_header.upper_layer_protocol == PROTOCOL_IPV6:
            print('  ', PROTOCOL_RARP, payload)
        else:
            print('  ', eth_header.upper_layer_protocol, payload)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
