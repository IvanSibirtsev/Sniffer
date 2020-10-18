import socket as s
import sys
from parsers.header_parsers import parser_determine
from parsers.arg_parser import Args
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


class Sniffer:
    def __init__(self, socket, args):
        self._socket = socket
        self._args = args
        self._full_packet = None

    def start_sniff(self):
        self.pcap_mod() if self._args.filename else self.console_mod()

    def console_mod(self):
        console = Console(self._args)
        count = 0
        while count < self._args.packets_count:
            data = self._socket.receive_from()
            self._full_packet = FullPacket(package_size := len(data))
            self._make_full_packet(data)
            console.main_method(self._full_packet)
            if console.printed:
                count += 1
        console.packet_report.show_report()
        print(console.packet_report.table)

    def _make_full_packet(self, data):
        protocol = 'Start'
        while not self._full_packet.full_packet.get('binary_data'):
            packet, data, protocol = parser_determine(data, protocol)
            self._full_packet.add_packet(packet)

    def pcap_mod(self):
        data = {i: self._socket.receive_from()
                for i in range(self._args.packet_count)}
        PcapFile(self._args.filename).write_pcap(data)


def main():
    parsed_args = Args()
    socket = Socket()
    sniffer = Sniffer(socket, parsed_args)
    try:
        sniffer.start_sniff()
    except KeyboardInterrupt:
        print("\nThat's all.")


if __name__ == '__main__':
    main()
