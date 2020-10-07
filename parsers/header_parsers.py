from struct import unpack
from headers import Ethernet, IPv4, IPv6, TCP, UDP, BinaryData, UnknownPacket


def parse_ethernet(data):
    d_mac, s_mac, ether_type = unpack('!6s6sH', data[:14])
    ethernet_header = Ethernet(s_mac, d_mac, ether_type)
    return ethernet_header, data[14:], ether_type


def parse_ipv4(data):
    (version_ihl, tos, total_len, datagram_id, flags_fr_offset, ttl,
     protocol, checksum, s_ip, d_ip) = unpack('!BBHHHBBH4s4s', data[0: 20])
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_len = ihl * 4

    flags = flags_fr_offset >> 13
    fr_offset = flags_fr_offset & 0xFF

    ipv4_header = IPv4(version, iph_len, tos, total_len, datagram_id, flags,
                       fr_offset, ttl, protocol, checksum, s_ip, d_ip)
    return ipv4_header, data[iph_len:], protocol


def parse_ipv6(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    payload_len, protocol, hop_limit = unpack('!HBB', data[4:8])
    s_ip = data[8:24]
    d_ip = data[24:40]

    ipv6_header = IPv6(version, payload_len, protocol, hop_limit, s_ip, d_ip)
    return ipv6_header, data[40:], protocol


def parser_determine(data, protocol):
    try:
        return protocol_to_parser[protocol](data)
    except KeyError:
        return parse_unknown_packet(data, protocol)


def parse_tcp(data):
    (s_port, d_port, sequence, acknowledgment,
     offset_reserved_flags) = unpack('!HHLLH', data[:14])
    tcp_header_len = data[12] >> 4
    window_size, checksum, urgent_point = unpack('!HHH', data[14: 20])
    offset = (offset_reserved_flags >> 12) * 4
    flags = parse_tcp_flags(offset_reserved_flags)

    tcp_header = TCP(s_port, d_port, sequence, acknowledgment, window_size,
                     checksum, urgent_point, flags)
    binary_data = BinaryData(data[offset:])
    return tcp_header, binary_data, 'End'


def parse_tcp_flags(offset_reserved_flags):
    urg = (offset_reserved_flags & 32) >> 5
    ack = (offset_reserved_flags & 16) >> 4
    psh = (offset_reserved_flags & 8) >> 3
    rst = (offset_reserved_flags & 4) >> 2
    syn = (offset_reserved_flags & 2) >> 1
    fin = offset_reserved_flags & 1
    return [urg, ack, psh, rst, syn, fin]


def parse_udp(data):
    s_port, d_port, length, checksum = unpack('!HHHH', data[:8])
    udp_header = UDP(s_port, d_port, length, checksum)
    binary_data = BinaryData(data[8:])
    return udp_header, binary_data, 'End'


def parse_unknown_packet(data, protocol):
    unknown = UnknownPacket(protocol, data)
    return unknown, unknown, 'End'  # \033[31m|


protocol_to_parser = {'Start': parse_ethernet, 2048: parse_ipv4, 17: parse_udp,
                      6: parse_tcp, 34525: parse_ipv6}
