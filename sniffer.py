import socket as s
from parsers.header_parsers import parser_determine
from parsers.arg_parser import parse_args, keys_parser
from output_format.pcap import MakePcap
from output_format.packet_filter import PacketFilter
from output_format.packet_report import PacketReport


def sniffer(args):
    try:
        socket = s.socket(s.AF_PACKET, s.SOCK_RAW, s.ntohs(3))
        packets_count = int(args.packets_count)
        if args.filename:
            data = {}
            for i in range(packets_count):
                data[i] = socket.recvfrom(655363)[0]
            pcap_mod(args.filename, data, packets_count)
        else:
            if packets_count == 1:
                packets_count = float('inf')
            logic_expression, specials, report, show_bytes = keys_parser(args)
            report = PacketReport(report)
            count = 0
            while count < packets_count:
                current_data = socket.recvfrom(655363)[0]
                count = console_mod(current_data, count, report,
                                    logic_expression, specials, show_bytes)
            report.show_report()
    except PermissionError:
        print('Try sudo')


def console_mod(data, count, report, logic_expression, specials, show_bytes):
    protocol = 'Start'
    final_packet = PacketFilter(logic_expression, specials)
    package_size = len(data)
    packet = None
    while protocol != 'End' and final_packet.flag:
        packet, data, protocol = parser_determine(data, protocol)
        final_packet.add(packet)
        report.add(packet, package_size)
    if not final_packet.flag:
        count += 1
    if (packet.packet_name in ['tcp', 'udp'] and
            show_bytes and data.binary_data):
        print(data.to_str())
    return count


def pcap_mod(filename, raw_data, packets_count):
    pcap_maker = MakePcap(filename)
    pcap_maker.write_packet(raw_data, packets_count)


def main():
    parsed_args = parse_args()
    sniffer(parsed_args)


if __name__ == '__main__':
    main()
