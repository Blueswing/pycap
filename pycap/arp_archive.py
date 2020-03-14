
def send_arp():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(('wlp3s0', 0))
    src_addr = b"\xac\xd1\xb8\xed\x5f\xb5"
    dst_addr = b"\xff\xff\xff\xff\xff\xff"
    ethertype = ETH_TYPE_ARP.to_bytes(2, 'big')
    hardware_type = b'\x00\x01'
    protocol_type = b'\x08\x00'
    hardware_addr_len = b"\x06"
    protocol_addr_len = b"\x04"
    """
    arp req 1
    arp res 2
    rarp req 3
    rarp res 4
    """

    # print(0x0806, socket.ntohs(0x0806), 0x0806.to_bytes(2, 'big'), 0x0806.to_bytes(2, 'little'))
    s.send(
        dst_addr + src_addr + ethertype + b"\x00\x01" + b"\x08\x00" + b"\x06" + b"\x04" + b"\x00\x01" + src_addr + b"\x7f\x00\x00\x01" + b"\x00\x00\x00\x00\x00\x00" + b"\x7f\x00\x00\x01")
