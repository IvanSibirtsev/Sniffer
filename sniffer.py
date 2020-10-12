import socket as s
from parsers.header_parsers import parser_determine
from parsers.arg_parser import parse_args, keys_parser
from output_format.pcap import PcapFile
from output_format.packet_filter import PacketFilter
from output_format.packet_report import PacketReport


def sniffer(args):
    try:
        socket = s.socket(s.AF_PACKET, s.SOCK_RAW, s.ntohs(3))
        if args.filename:
            pcap_mod(socket, args)
        else:
            console_mod(socket, args)
    except PermissionError:
        print('Try sudo')


def console_mod(socket, args):
    logic_expression, specials, report, show_bytes = keys_parser(args)
    report = PacketReport(report)
    count = 0
    packets_count = args.packets_count
    if args.packets_count == 1:
        packets_count = float('inf')
    while count < packets_count:
        data = socket.recvfrom(655363)[0]
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
    report.show_report()


def pcap_mod(socket, args):
    data = {}
    for i in range(args.packets_count):
        data[i] = socket.recvfrom(655363)[0]
    PcapFile(args.filename).write_pcap(data, args.packets_count)


def main():
    parsed_args = parse_args()
    sniffer(parsed_args)


if __name__ == '__main__':
    main()
