import socket

BIG_ENDIAN = 'big'
LITTLE_ENDIAN = 'little'

ETH_P_ALL = 0x3

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_RARP = 0x8035
ETH_P_IPV6 = 0x086dd

ETH_TYPE_MAP = {
    ETH_P_IP: 'IP',
    ETH_P_ARP: 'ARP',
    ETH_P_RARP: 'RARP',
    ETH_P_IPV6: 'IPv6'
}
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

class MACAddress:
    def __init__(self, addr: int):
        self.addr = addr

    def __str__(self):
        return ':'.join('{:02x}'.format(a) for a in self.addr.to_bytes(6, BIG_ENDIAN))

    def __repr__(self):
        return self.__str__()


class EthernetHeader:

    def __init__(self, dst_mac, src_mac):
        self.dst_mac = dst_mac
        self.src_mac = src_mac

    def describe(self):
        return {
            'src_mac': MACAddress(self.src_mac),
            'dst_mac': MACAddress(self.dst_mac)
        }


class EthernetIIHeader(EthernetHeader):

    def __init__(self, dst_mac, src_mac):
        super().__init__(dst_mac, src_mac)
        self.eth_type = 0

    def describe(self):
        dct = super().describe()
        dct['eth_type'] = self._describe_eth_type(self.eth_type)
        return dct

    @staticmethod
    def _describe_eth_type(eth_type):
        if eth_type in ETH_TYPE_MAP:
            return ETH_TYPE_MAP[eth_type]
        return 'Unknown protocol {}'.format(eth_type)


class Ethernet802_3Header(EthernetHeader):

    def __init__(self, dst_mac, src_mac):
        super().__init__(dst_mac, src_mac)
        self.length = 0
        self.llc = 0
        self.snap = 0

    def describe(self):
        dct = super().describe()
        dct['length'] = self.length
        dct['llc'] = self.llc
        dct['snap'] = self.snap
        return dct


def unpack(packet):
    dst_mac = int.from_bytes(packet[:6], BIG_ENDIAN)
    src_mac = int.from_bytes(packet[6:12], BIG_ENDIAN)
    if dst_mac == 0 or src_mac == 0:
        print(packet)
    type_or_length = int.from_bytes(packet[12:14], BIG_ENDIAN)
    if type_or_length <= 1500:
        """
        IEEE 802.3 帧长度字段值小于等于1500 (0x05DC)
        IEEE 802.3帧格式类似于Ethernet_II帧，只是Ethernet_II帧的Type域被802.3帧的Length域取代，并且占用了Data字段的8个字节作为LLC和SNAP字段。
        Length字段定义了Data字段包含的字节数。
        逻辑链路控制LLC（Logical Link Control）由目的服务访问点DSAP（Destination Service Access Point）、源服务访问点SSAP（Source Service Access Point）和Control字段组成。
        SNAP（Sub-network Access Protocol）由机构代码（Org Code）和类型（Type）字段组成。Org code三个字节都为0。Type字段的含义与Ethernet_II帧中的Type字段相同。IEEE802.3帧根据DSAP和SSAP字段的取值又可分为以下几类：
        当DSAP和SSAP都取特定值0xff时，802.3帧就变成了Netware-ETHERNET帧，用来承载NetWare类型的数据。
        当DSAP和SSAP都取特定值0xaa时，802.3帧就变成了ETHERNET_SNAP帧。ETHERNET_SNAP帧可以用于传输多种协议。
        DSAP和SSAP其他的取值均为纯IEEE802.3帧。
        """
        hdr = Ethernet802_3Header(dst_mac, src_mac)
        hdr.length = type_or_length
        hdr.llc = int.from_bytes(packet[14:17], BIG_ENDIAN)
        hdr.snap = int.from_bytes(packet[17:22], BIG_ENDIAN)
        return hdr, packet[22:]

    elif type_or_length >= 1536:
        """
        Ethernet_II 帧类型值大于等于1536 (0x0600)
        以太网数据帧的长度在64-1518字节之间
        Ethernet_II的帧中各字段说明如下：
        DMAC（Destination MAC）是目的MAC地址。DMAC字段长度为6个字节，标识帧的接收者。
        SMAC（Source MAC）是源MAC地址。SMAC字段长度为6个字节，标识帧的发送者。
        类型字段（Type）用于标识数据字段中包含的高层协议，该字段长度为2个字节。类型字段取值为0x0800的帧代表IP协议帧；类型字段取值为0806的帧代表ARP协议帧。
        数据字段(Data)是网络层数据，最小长度必须为46字节以保证帧长至少为64字节，数据字段的最大长度为1500字节。
        循环冗余校验字段（FCS）提供了一种错误检测机制。该字段长度为4个字节。
        """
        hdr = EthernetIIHeader(dst_mac, src_mac)
        hdr.eth_type = type_or_length
        return hdr, packet[14:]
    else:
        raise ValueError(type_or_length)


def main():
    raw_sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    while True:
        try:
            packet, packet_info = raw_sock.recvfrom(1800)
            eth_header, payload = unpack(packet)
            print(eth_header.describe(), payload)
        except KeyboardInterrupt:
            break
        except ValueError as e:
            print('unpack failed', e)


if __name__ == '__main__':
    main()
