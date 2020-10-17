import socket as s
import sys
from parsers.header_parsers import parser_determine
from parsers.arg_parser import parse_args
from output_format.pcap import PcapFile
from full_packet import FullPacket
from output_format.console import Console


class Socket:
    ALL_DATA = 65565

    def __init__(self):
        try:
            self.socket = s.socket(s.AF_PACKET, s.SOCK_RAW, s.ntohs(3))
        except AttributeError:
            print('Use Linux.')
            sys.exit()

    def receive_from(self):
        try:
            return self.socket.recvfrom(self.ALL_DATA)[0]
        except PermissionError:
            print('Try sudo.')
            sys.exit()


def sniffer(args):
    socket = Socket()
    pcap_mod(socket, args) if args.filename else console_mod(socket, args)


def console_mod(socket, args):
    console = Console(args)
    count = 0
    while count < args.packets_count:
        data = socket.receive_from()
        full_packet = FullPacket(package_size := len(data))
        make_full_packet(full_packet, data)
        console.main_method(full_packet)
        if console.printed:
            count += 1
    console.packet_report.show_report()
    print(console.packet_report.table)


def make_full_packet(full_packet, data):
    protocol = 'Start'
    while not full_packet.full_packet.get('binary_data'):
        packet, data, protocol = parser_determine(data, protocol)
        full_packet.add_packet(packet)


def pcap_mod(socket, args):
    data = {i: socket.receive_from() for i in range(args.packet_count)}
    PcapFile(args.filename).write_pcap(data)


def main():
    parsed_args = parse_args()
    try:
        sniffer(parsed_args)
    except KeyboardInterrupt:
        print("\nThat's all.")


if __name__ == '__main__':
    main()
