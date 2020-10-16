import io
import hexdump
from contextlib import redirect_stdout

TAB_1 = '|\t- '
TAB_2 = '|\t\t- '
TAB_3 = '|\t\t\t- '


class Ethernet:
    def __init__(self, src, destination, ether_type):
        self.level = 'data_link'
        self.packet_name = 'eth'
        self.s_mac = self.get_mac(src)
        self.d_mac = self.get_mac(destination)
        self.ether_type = ether_type

    @staticmethod
    def get_mac(a):
        return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            a[0], a[1], a[2], a[3], a[4], a[5])

    def get_all_ethernet_information(self):
        return self.s_mac, self.d_mac, self.ether_type

    def to_str(self):
        s = '| Ethernet:\n'
        s += (TAB_1 + f'Destination MAC: {self.s_mac}, ' +
              f'Source MAC: {self.d_mac}, Protocol: {self.ether_type}.')
        return s


class IPv4:
    def __init__(self, version, iph_len, tos, total_len, datagram_id, flags,
                 fr_offset, ttl, protocol, checksum, source, destination):
        # region init
        self.level = 'network'
        self.packet_name = 'ipv4'
        self.version = version
        self.iph_len = iph_len
        self.tos = tos
        self.total_len = total_len
        self.datagram_id = datagram_id
        self.flags = flags
        self.fr_offset = fr_offset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.s_ip = str(self.get_ipv4(source))
        self.d_ip = str(self.get_ipv4(destination))
        # endregion init

    @staticmethod
    def get_ipv4(address):
        return '.'.join(map(str, address))

    def get_all_ipv4_information(self):
        return (self.version, self.iph_len, self.tos, self.total_len,
                self.datagram_id, self.flags, self.fr_offset, self.ttl,
                self.protocol, self.checksum, self.s_ip, self.d_ip)

    def to_str(self):
        s = '| IPv4:\n' + TAB_1
        s += f'Version: {self.version}, Header Length: {self.iph_len}, ' \
            f'ToS/DSCP: {self.tos}, Total Length: {self.total_len}, ' \
            f'Identificator: {self.datagram_id}.\n' + TAB_1
        s += f'Flags: {self.flags}, Fragmentation Offset: {self.fr_offset},' \
            f' TTL: {self.ttl}, Protocol: {self.protocol}, ' \
            f'Header Checksum: {self.checksum}.\n' + TAB_1
        s += f'Source IP: {self.s_ip}, Destination IP: {self.d_ip}.'
        return s


class IPv6:
    def __init__(self, version,  payload_label, protocol, ttl,
                 source, destination):
        self.level = 'network'
        self.packet_name = 'ipv6'
        self.version = version
        self.payload_label = payload_label
        self.protocol = protocol
        self.ttl = ttl
        self.s_ip = str(self.get_ipv6(source))
        self.d_ip = str(self.get_ipv6(destination))

    @staticmethod
    def get_ipv6(address):
        a = ''.join(map('{:02X}'.format, address))
        return (f'{a[0:4]}:{a[4:8]}:{a[8:12]}:{a[12:16]}:{a[16:20]}'
                f':{a[20:24]}:{a[24:28]}:{a[28:32]}')

    def get_all_information(self):
        return (self.version, self.payload_label, self.protocol, self.ttl,
                self.s_ip, self.d_ip)

    def to_str(self):
        s = '| IPv6:\n' + TAB_1
        s += f'Version: {self.version}, Payload label: {self.payload_label}.\n'
        s += TAB_1 + f'Protocol: {self.protocol}, TTL: {self.ttl}.\n' + TAB_1
        s += f'Source IP: {self.s_ip}, Destination IP: {self.d_ip}.'
        return s


class TCP:
    def __init__(self, s_port, d_port, sequence, acknowledgment, window_size,
                 checksum, urgent_point, flags):
        self.level = 'transport'
        self.packet_name = 'tcp'
        self.s_port = str(s_port)
        self.d_port = str(d_port)
        self.seq = sequence
        self.acknowledgment = acknowledgment
        self.w_size = window_size
        self.checksum = checksum
        self.urgent_point = urgent_point
        self.f = flags

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
    def __init__(self, s_port, d_port, length, checksum):
        self.level = 'transport'
        self.packet_name = 'udp'
        self.s_port = str(s_port)
        self.d_port = str(d_port)
        self.length = length
        self.checksum = checksum

    def get_all_udp_information(self):
        return self.s_port, self.d_port, self.length, self.checksum

    def to_str(self):
        s = '| UDP Segment:\n' + TAB_1
        s += f'Source Port: {self.s_port}, Destination Port: {self.d_port}.\n'
        s += TAB_1 + f'Length: {self.length}, Checksum: {self.checksum}.'
        return s


class BinaryData:
    def __init__(self, binary_data):
        self.packet_name = 'binary_data'
        self.binary_data = binary_data

    def to_str(self):
        s = HexDump(self.binary_data).hex_string
        return '| Data:\n' + str(s)


class UnknownNetworkPacket:
    def __init__(self, protocol, binary_data):
        self.level = 'unknown'
        self.protocol = protocol
        self.binary_data = binary_data

    def to_str(self):
        s = HexDump(self.binary_data).hex_string
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
        self.s_ip = 'unknown'
        self.d_ip = 'unknown'


class HexDump:
    def __init__(self, binary_data):
        with io.StringIO() as buf, redirect_stdout(buf):
            generator = hexdump.hexdump(binary_data, 'generator')
            for line in generator:
                print('| ' + line)
            self.hex_string = buf.getvalue()
