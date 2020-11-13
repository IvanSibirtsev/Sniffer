import os
from pcap.pcap_headers import GlobalHeader, PacketHeader


class PcapFile:
    def __init__(self, filename=''):
        self.filename = 'pcap_file.pcap_files' if not filename else filename
        self.file = self._create_and_open_file()
        print(f'pcap_files file: {self.filename}')
        self._write_global_header()

    def _create_and_open_file(self):
        return open(os.path.join('pcap_files', self.filename), 'wb+')

    def _write_global_header(self):
        global_header = GlobalHeader()
        for x in global_header():
            self.file.write(x)

    def write_pcap(self, raw_packet):
        for key in raw_packet.keys():
            self._write_packet(raw_packet.get(key))
        self.file.close()

    def _write_packet(self, packet):
        self._write_packet_header(packet)
        self.file.write(packet)

    def _write_packet_header(self, packet):
        packet_header = PacketHeader(packet)
        for x in packet_header():
            self.file.write(x)
