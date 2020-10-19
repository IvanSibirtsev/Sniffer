from struct import unpack
import hexdump
import io
from contextlib import redirect_stdout


TAB_1 = '|\t- '
TAB_2 = '|\t\t- '
TAB_3 = '|\t\t\t- '


class Ethernet:
    def __init__(self, data):
        self.data = data
        self.level = 'data_link'
        self.packet_name = 'eth'
        self.s_mac = ''
        self.d_mac = ''
        self.next_header = ''

    def parse(self):
        d_mac, s_mac, self.next_header = unpack('!6s6sH', self.data[:14])
        self.s_mac = self.get_mac(s_mac)
        self.d_mac = self.get_mac(d_mac)
        self.data = self.data[14:]
        return self

    @staticmethod
    def get_mac(a):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            a[0], a[1], a[2], a[3], a[4], a[5])

    def get_all_ethernet_information(self):
        return self.s_mac, self.d_mac, self.next_header

    def to_str(self):
        s = '| Ethernet:\n'
        s += (TAB_1 + f'Destination MAC: {self.s_mac}, ' +
              f'Source MAC: {self.d_mac}, Protocol: {self.next_header}.')
        return s


class IPv4:
    def __init__(self, data):
        # region init
        self.data = data
        self.level = 'network'
        self.packet_name = 'ipv4'
        self.version = ''
        self.iph_len = ''
        self.tos = ''
        self.total_len = ''
        self.datagram_id = ''
        self.flags = ''
        self.fr_offset = ''
        self.ttl = ''
        self.next_header = ''
        self.checksum = ''
        self.s_ip = ''
        self.d_ip = ''
        # endregion init

    def parse(self):
        (version_ihl, self.tos, self.total_len, self.datagram_id,
         flags_fr_offset, self.ttl, self.next_header, self.checksum,
         s_ip, d_ip) = unpack('!BBHHHBBH4s4s', self.data[0:20])
        self.s_ip = str(self.get_ipv4(s_ip))
        self.d_ip = str(self.get_ipv4(d_ip))

        self.version = version_ihl >> 4
        ihl = version_ihl & 0xF
        self.iph_len = ihl * 4

        self.flags = flags_fr_offset >> 13
        self.fr_offset = flags_fr_offset & 0xFF

        self.data = self.data[self.iph_len:]
        return self

    @staticmethod
    def get_ipv4(address):
        return '.'.join(map(str, address))

    def get_all_ipv4_information(self):
        return (self.version, self.iph_len, self.tos, self.total_len,
                self.datagram_id, self.flags, self.fr_offset, self.ttl,
                self.next_header, self.checksum, self.s_ip, self.d_ip)

    def to_str(self):
        s = '| IPv4:\n' + TAB_1
        s += f'Version: {self.version}, Header Length: {self.iph_len}, ' \
            f'ToS/DSCP: {self.tos}, Total Length: {self.total_len}, ' \
            f'Identificator: {self.datagram_id}.\n' + TAB_1
        s += f'Flags: {self.flags}, Fragmentation Offset: {self.fr_offset},' \
            f' TTL: {self.ttl}, Protocol: {self.next_header}, ' \
            f'Header Checksum: {self.checksum}.\n' + TAB_1
        s += f'Source IP: {self.s_ip}, Destination IP: {self.d_ip}.'
        return s


class IPv6:
    def __init__(self, data):
        self.data = data
        self.level = 'network'
        self.packet_name = 'ipv6'
        self.version = ''
        self.payload_label = ''
        self.next_header = ''
        self.ttl = ''
        self.s_ip = ''
        self.d_ip = ''

    def parse(self):
        version_header_len = self.data[0]
        self.version = version_header_len >> 4
        payload_proto_limit = unpack('!HBB', self.data[4:8])
        self.payload_label = payload_proto_limit[0]
        self.next_header = payload_proto_limit[1]
        self.ttl = payload_proto_limit[0]
        self.s_ip = str(self.get_ipv6(self.data[8:24]))
        self.d_ip = str(self.get_ipv6(self.data[24:40]))
        self.data = self.data[40:]
        return self

    @staticmethod
    def get_ipv6(address):
        a = ''.join(map('{:02X}'.format, address))
        return (f'{a[0:4]}:{a[4:8]}:{a[8:12]}:{a[12:16]}:{a[16:20]}'
                f':{a[20:24]}:{a[24:28]}:{a[28:32]}')

    def get_all_information(self):
        return (self.version, self.payload_label, self.next_header, self.ttl,
                self.s_ip, self.d_ip)

    def to_str(self):
        s = '| IPv6:\n' + TAB_1
        s += f'Version: {self.version}, Payload label: {self.payload_label}.\n'
        s += TAB_1 + f'Protocol: {self.next_header}, TTL: {self.ttl}.\n' + TAB_1
        s += f'Source IP: {self.s_ip}, Destination IP: {self.d_ip}.'
        return s


class TCP:
    def __init__(self, data):
        self.data = data
        self.level = 'transport'
        self.packet_name = 'tcp'
        self.next_header = 'binary_data'
        self.s_port = ''
        self.d_port = ''
        self.seq = ''
        self.acknowledgment = ''
        self.w_size = ''
        self.checksum = ''
        self.urgent_point = ''
        self.f = []

    def parse(self):
        (s_port, d_port, self.seq, self.acknowledgment,
         offset_reserved_flags) = unpack('!HHLLH', self.data[:14])
        tcp_header_len = self.data[12] >> 4
        self.s_port = str(s_port)
        self.d_port = str(d_port)
        (self.w_size, self.checksum,
         self.urgent_point) = unpack('!HHH', self.data[14: 20])
        offset = (offset_reserved_flags >> 12) * 4
        self.f = self.parse_tcp_flags(offset_reserved_flags)
        self.data = self.data[offset:]
        return self

    @staticmethod
    def parse_tcp_flags(offset_reserved_flags):
        urg = (offset_reserved_flags & 32) >> 5
        ack = (offset_reserved_flags & 16) >> 4
        psh = (offset_reserved_flags & 8) >> 3
        rst = (offset_reserved_flags & 4) >> 2
        syn = (offset_reserved_flags & 2) >> 1
        fin = offset_reserved_flags & 1
        return [urg, ack, psh, rst, syn, fin]

    def get_all_tcp_information(self):
        return (self.s_port, self.d_port, self.seq, self.acknowledgment,
                self.w_size, self.checksum, self.urgent_point, self.f)

    def to_str(self):
        s = '| TCP Segment:\n' + TAB_1
        s += f'Source Port: {self.s_port}, Destination Port: {self.d_port}\n'
        s += TAB_1
        s += f'Sequence: {self.seq}, Acknowledgment: {self.acknowledgment}, ' \
            f'Window Size: {self.w_size}\n' + TAB_1
        s += f'Checksum: {self.checksum}, Urgent Point: {self.urgent_point}.\n'
        s += TAB_1 + 'Flags:\n'
        s += TAB_2 + f'URG: {self.f[0]}, ACK: {self.f[1]}, PSH: {self.f[2]}\n'
        s += TAB_2 + f'RST: {self.f[3]}, SYN: {self.f[4]}, FIN: {self.f[5]}'
        return s


class UDP:
    def __init__(self, data):
        self.data = data
        self.level = 'transport'
        self.packet_name = 'udp'
        self.next_header = 'binary_data'
        self.s_port = ''
        self.d_port = ''
        self.length = ''
        self.checksum = ''

    def parse(self):
        (s_port, d_port, self.length,
         self.checksum) = unpack('!HHHH', self.data[:8])
        self.s_port = str(s_port)
        self.d_port = str(d_port)
        self.data = self.data[8:]
        return self

    def get_all_udp_information(self):
        return self.s_port, self.d_port, self.length, self.checksum

    def to_str(self):
        s = '| UDP Segment:\n' + TAB_1
        s += f'Source Port: {self.s_port}, Destination Port: {self.d_port}.\n'
        s += TAB_1 + f'Length: {self.length}, Checksum: {self.checksum}.'
        return s


class BinaryData:
    def __init__(self, data):
        self.data = data
        self.level = 'binary_data'
        self.packet_name = 'binary_data'
        self.next_header = ''

    def parse(self):
        return self

    def to_str(self):
        s = HexDump(self.data).hex_string
        return '| Data:\n' + str(s)


class UnknownPacket:
    def __init__(self, protocol, data):
        self.level = 'unknown'
        self.protocol = protocol
        self.data = data
        self.next_header = ''

    def to_str(self):
        s = HexDump(self.data).hex_string
        return f'| Unknown protocol number: {self.protocol}\n' + str(s)


class NullNetworkPacket:
    def __init__(self):
        self.level = 'network'
        self.packet_name = 'UnknownNetworkPacket'
        self.s_ip = 'unknown'
        self.d_ip = 'unknown'


class NullTransportPacket:
    def __init__(self):
        self.level = 'transport'
        self.packet_name = 'UnknownTransportPacket'
        self.port = 'unknown'


class HexDump:
    def __init__(self, binary_data):
        with io.StringIO() as buf, redirect_stdout(buf):
            generator = hexdump.hexdump(binary_data, 'generator')
            for line in generator:
                print('| ' + line)
            self.hex_string = buf.getvalue()
