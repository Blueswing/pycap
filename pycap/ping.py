import select
import socket
import struct
import time
import uuid
from collections import deque

from .icmp import parse_icmp_packet
from .ip import get_ip_address, parse_ipv4_packet

_FMT_ICMP_PACKET = '>BBHHH'


def chesksum(data):
    n = len(data)
    m = n % 2
    sum_ = 0
    for i in range(0, n - m, 2):
        # 传入data以每两个字节（十六进制）通过ord转十进制，第一字节在低位，第二个字节在高位
        sum_ += (data[i]) + ((data[i + 1]) << 8)
    if m:
        sum_ += (data[-1])
    # 将高于16位与低16位相加
    sum_ = (sum_ >> 16) + (sum_ & 0xffff)
    # 如果还有高于16位，将继续与低16位相加
    sum_ += (sum_ >> 16)
    answer = ~sum_ & 0xffff
    #  主机字节序转网络字节序列（参考小端序转大端序）
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def dealtime(dst_addr, sumtime, shorttime, longtime, accept, i, time):
    sumtime += time
    print(sumtime)
    if i == 4:
        print("{0}的Ping统计信息：".format(dst_addr))
        msg = "数据包：已发送={0},接收={1}，丢失={2}（{3}%丢失），\n往返行程的估计时间（以毫秒为单位）：\n\t最短={4}ms，最长={5}ms，平均={6}ms"
        print(msg.format(i + 1, accept, i + 1 - accept, (i + 1 - accept) / (i + 1) * 100, shorttime, longtime, sumtime))


class TimedData:

    def __init__(self, data, ts):
        self.data = data
        self.ts = ts


class MovingStatistic:
    def __init__(self, duration):
        self._duration = duration
        self._q = deque()

    def update(self, data):
        now = time.time()
        self._q.append(TimedData(data, now))
        while len(self._q) > 0 and now - self._q[0].ts > self._duration:
            self._q.popleft()


class PingStat(MovingStatistic):

    def total(self):
        return len(self._q)

    # def success(self):
    #     return sum(err is None for _, err in self._q)

    def failure(self):
        return sum(item.data[1] is not None for item in self._q)

    def failure_ratio(self):
        total = self.total()
        if total == 0:
            return 0.0
        return self.failure() / total

    def time_avg(self):
        cnt = 0
        sum_t = 0.0
        for item in self._q:
            t, err = item.data
            if err is None:
                cnt += 1
                sum_t += t
        if cnt == 0:
            return 0.0
        return sum_t / cnt


def _get_random_payload(length):
    if length == 0:
        return b''
    n = (length // 16) + 1
    if n == 1:
        return uuid.uuid4().bytes[:length]
    else:
        return (uuid.uuid4().bytes * n)[:length]


def ping(addr: str, interval=3.0, timeout=3.0):
    stat = PingStat(60.0)
    rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    data_sequence = 1
    while True:
        time_elapsed, err = _ping_once(rawsocket, addr, data_sequence, _get_random_payload(64), timeout)
        data_sequence = (data_sequence + 1) % 0xffff
        stat.update((time_elapsed, err))
        total = stat.total()
        fail = stat.failure()
        print('total:', total, ', failed:', fail, ', average time:', stat.time_avg())
        time.sleep(interval)


def _ping_once(rawsocket, addr, data_sequence, payload, timeout):
    try:
        dst_addr = str(get_ip_address(addr))
    except Exception as e:
        return timeout, f'failed to resolve domain, {e}'
    data_type = 8
    data_code = 0
    data_id = 0
    icmp_packet = build_icmp_packet(data_type, data_code, data_id, data_sequence, payload)
    t0 = time.time()
    rawsocket.sendto(icmp_packet, (dst_addr, 0))
    while True:
        time_elapsed = time.time() - t0
        if time_elapsed >= timeout:
            return timeout, 'timeout'
        rlist, _, _ = select.select([rawsocket], [], [], timeout - time_elapsed)
        if len(rlist) == 0:
            return timeout, 'timeout'
        data, _ = rawsocket.recvfrom(1500)
        time_elapsed = time.time() - t0
        header, ip_payload = parse_ipv4_packet(data)
        if header.protocol == 'icmp':
            icmp_header, res_payload = parse_icmp_packet(ip_payload)
            if payload == res_payload:
                return time_elapsed, None
            else:
                continue
        else:
            continue


def build_icmp_packet(data_type, data_code, data_id, data_seq, payload):
    l_payload = len(payload)
    if l_payload == 0:
        icmp_packet = struct.pack(_FMT_ICMP_PACKET, data_type, data_code, 0, data_id, data_seq)
        icmp_chesksum = chesksum(icmp_packet)
        icmp_packet = struct.pack(_FMT_ICMP_PACKET, data_type, data_code, icmp_chesksum, data_id, data_seq)
    else:
        fmt = _FMT_ICMP_PACKET + f'{l_payload}s'
        icmp_packet = struct.pack(fmt, data_type, data_code, 0, data_id, data_seq, payload)
        icmp_chesksum = chesksum(icmp_packet)
        icmp_packet = struct.pack(fmt, data_type, data_code, icmp_chesksum, data_id, data_seq, payload)
    return icmp_packet


def play_packet():
    # print(socket.getaddrinfo(socket.gethostname(), None, family=socket.AddressFamily.AF_INET))
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind(('wlp3s0', socket.htons(0x0800)))
    header = struct.pack('>6s6s2s', b'\xaa\xaa\xaa\xaa\xaa\xaa', b'\xbb\xbb\xbb\xbb\xbb\xbb', b'\x08\x00')
    packet = header + b'hello, world!'
    sock.send(packet)
    print(packet)
    # print(res)
    sock.close()


def arp_boardcast():
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind(('wlp3s0', socket.htons(0x0800)))
    ether_type = b'\x08\x06'
    header = struct.pack('>6s6s2s', b'\xff\xff\xff\xff\xff\xff', b'\xbb\xbb\xbb\xbb\xbb\xbb', ether_type)
