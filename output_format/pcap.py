from struct import pack
import time
import os


class PcapFile:
    GMT = -5
    MAX_PACKET_LEN = 65535

    def __init__(self, filename=''):
        self.filename = 'pcap_file.pcap' if not filename else filename
        self.file = self.create_and_open_file()
        self.this_zone = self.GMT * 3600
        self.snapshot_len = self.MAX_PACKET_LEN
        print(f'pcap file: {self.filename}')
        self.write_global_header()

    def create_and_open_file(self):
        return open(os.path.join('../pcap', self.filename), 'wb+')

    def write_global_header(self):
        global_header = GlobalHeader(self.this_zone,
                                     self.snapshot_len).global_header
        for x in global_header:
            self.file.write(x)

    def write_pcap(self, raw_packet, packets_count):
        for i in range(packets_count):
            self.write_packet(raw_packet[i])
        self.file.close()

    def write_packet(self, packet):
        self.write_packet_header(packet)
        self.file.write(packet)

    def write_packet_header(self, packet):
        packet_header = PacketHeader(packet,
                                     self.snapshot_len).packet_header
        for x in packet_header:
            self.file.write(x)


class GlobalHeader:
    ETHERNET = "d4c3b2a1"
    EMPTY_BYTES = b"\x00"

    def __init__(self, this_zone, snapshot_len):
        self.something = bytes.fromhex(self.ETHERNET)
        self.major_version = pack("H", 2)
        self.minor_version = pack('H', 4)
        self.this_zone = pack("i", this_zone)
        self.sigfigs = self.EMPTY_BYTES * 4
        self.snap_len = pack("i", snapshot_len)
        self.network = pack("i", 1)
        self.global_header = self._get_global_header()

    def _get_global_header(self):
        return [self.something, self.major_version, self.minor_version,
                self.this_zone, self.sigfigs, self.snap_len, self.network]


class PacketHeader:
    def __init__(self, packet, snapshot_len):
        self.ts_sec = pack("i", int(time.time()))
        self.ts_usec = pack("i", 0)
        self.incl_len = pack("i", len(packet) % snapshot_len)
        self.orig_len = pack("i", len(packet))
        self.packet_header = self._get_packet_header()

    def _get_packet_header(self):
        return [self.ts_sec, self.ts_usec, self.incl_len, self.orig_len]
