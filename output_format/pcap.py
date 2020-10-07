from struct import pack
from time import time
import os
ETHERNET = "d4c3b2a1"


class MakePcap:
    def __init__(self, filename=''):
        self.filename = 'pcap_file.pcap' if not filename else filename
        self.file = self.create_pcap_file()
        self.this_zone = -5 * 3600
        self.snapshot_len = 65535

        print(f'pcap file: {self.filename}')
        self.write_global_header()

    def create_pcap_file(self):
        return open(os.path.join('../pcap', self.filename), 'wb+')

    def write_global_header(self):
        something = bytes.fromhex(ETHERNET)
        major_version, minor_version = pack("H", 2), pack('H', 4)
        this_zone = pack("i", self.this_zone)
        sigfigs = b"\x00" * 4
        snap_len = pack("i", self.snapshot_len)
        network = pack("i", 1)

        bin_data = [something, major_version, minor_version, this_zone,
                    sigfigs, snap_len, network]

        for x in bin_data:
            self.file.write(x)

    def write_packet(self, raw_packet, packets_count):
        for i in range(packets_count):
            self.write_packet_header(raw_packet[i])
            self.file.write(raw_packet[i])
        self.file.close()

    def write_packet_header(self, packet):
        ts_sec = pack("i", int(time()))
        ts_usec = pack("i", 0)
        incl_len = pack("i", len(packet) % self.snapshot_len)
        orig_len = pack("i", len(packet))

        bin_data = [ts_sec, ts_usec, incl_len, orig_len]

        for x in bin_data:
            self.file.write(x)
