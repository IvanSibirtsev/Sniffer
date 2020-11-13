from struct import pack
import time


MAX_PACKET_LEN = 65535
GMT = -5


class GlobalHeader:
    ETHERNET = "d4c3b2a1"
    EMPTY_BYTES = b"\x00"

    def __init__(self):
        self.something = bytes.fromhex(self.ETHERNET)
        self.major_version = pack("H", 2)
        self.minor_version = pack('H', 4)
        self.time_zone = pack("i", GMT * 3600)
        self.sigfigs = self.EMPTY_BYTES * 4
        self.snap_len = pack("i", MAX_PACKET_LEN)
        self.network = pack("i", 1)

    def __call__(self):
        return [self.something, self.major_version, self.minor_version,
                self.time_zone, self.sigfigs, self.snap_len, self.network]


class PacketHeader:
    def __init__(self, packet):
        self.ts_sec = pack("i", int(time.time()))
        self.ts_usec = pack("i", 0)
        self.incl_len = pack("i", len(packet) % MAX_PACKET_LEN)
        self.orig_len = pack("i", len(packet))

    def __call__(self):
        return [self.ts_sec, self.ts_usec, self.incl_len, self.orig_len]
