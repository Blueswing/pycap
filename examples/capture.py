from pycap import new_ethernet_sniffer_socket, new_ip_sniffer_socket
from pycap.arp import ARP
from pycap.constants import PROTOCOL_IP, PROTOCOL_TCP, PROTOCOL_ARP, PROTOCOL_IPV6, \
    PROTOCOL_ICMP, PROTOCOL_UDP, PROTOCOL_DNS, PROTOCOL_ETH
from pycap.dns import DNS
from pycap.ethernet import parse_ethernet_packet_info, Ethernet
from pycap.icmp import ICMP
from pycap.ip import IP, IPv6, IPv4Address
from pycap.tcp import TCP
from pycap.udp import UDP

ethernet = Ethernet()
ip = IP()
PROTOCOL_DICT = {
    PROTOCOL_ETH: ethernet,
    PROTOCOL_ARP: ARP(),
    PROTOCOL_IP: ip,
    PROTOCOL_IPV6: IPv6(),
    PROTOCOL_ICMP: ICMP(),
    PROTOCOL_UDP: UDP(),
    PROTOCOL_DNS: DNS(),
    PROTOCOL_TCP: TCP()
}


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
        print('Packet', packet_info.describe())
        hdr, payload = ethernet.unpack_data(packet)
        prefix = '  '
        print(prefix, PROTOCOL_ETH, hdr.describe())
        while hdr.upper_layer_protocol in PROTOCOL_DICT:
            upper_proto = hdr.upper_layer_protocol
            proto = PROTOCOL_DICT[upper_proto]
            hdr, payload = proto.unpack_data(payload)
            prefix += '  '
            print(prefix, upper_proto, hdr.describe())
        print(prefix + '  ', 'payload', payload)


def demo_ip():
    sniffer = new_ip_sniffer_socket()
    while True:
        packet, address_info = sniffer.recvfrom(1500)
        hdr, payload = ip.unpack_data(packet)
        prefix = ''
        if hdr.upper_layer_protocol == PROTOCOL_UDP:
            # print(prefix, PROTOCOL_IP, hdr.describe())
            while hdr.upper_layer_protocol in PROTOCOL_DICT:
                upper_proto = hdr.upper_layer_protocol
                proto = PROTOCOL_DICT[upper_proto]
                hdr, payload = proto.unpack_data(payload)
                prefix += '  '
                # if proto == PROTOCOL_DNS:
                print(prefix, upper_proto, hdr.describe(), payload)
            # print(prefix + '  ', 'payload', payload)


if __name__ == '__main__':
    try:
        demo_ip()
        # main()
    except KeyboardInterrupt:
        pass
