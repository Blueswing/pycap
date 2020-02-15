from pycap import new_ethernet_sniffer_socket
from pycap.constants import PROTOCOL_ETH, PROTOCOL_IP
from pycap.ethernet import parse_ethernet_packet_info, unpack_ethernet_packet

from pycap.ip import unpack_ip_packet


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
        print('info', packet_info)
        eth_header, payload = unpack_ethernet_packet(packet)
        print(PROTOCOL_ETH, eth_header, payload)
        if eth_header.eth_type == PROTOCOL_IP:
            ip_header, ip_payload = unpack_ip_packet(payload)
            print(PROTOCOL_IP, ip_header, ip_payload)
            # if ip_header.protocol == 'tcp':
            #     tcp_header, tcp_payload = parse_tcp_packet(ip_payload)
            #     print('tcp', tcp_header)
            # elif ip_header.protocol == 'icmp':
            #     print('icmp', parse_icmp_packet(ip_payload))
        # elif eth_header.eth_type == 'arp':
        #     print('arp', payload)
        # elif eth_header.eth_type == 'rarp':
        #     print('rarp', payload)
        # elif eth_header.eth_type == 'ipv6':
        #     print('ipv6', payload)
        # else:
        #     print('parser not found', eth_header.eth_type)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
