from packets.headers import NullNetworkPacket, NullTransportPacket


class FullPacket:
    def __init__(self, size):
        self.full_packet = {}
        self.packet_size = size

    def add_packet(self, packet):
        if packet.level == 'unknown':
            self.full_packet['binary_data'] = packet
        else:
            self.full_packet[packet.level] = packet

    def _add_missed_packets(self):
        if 'network' not in self.full_packet.keys():
            self.full_packet['network'] = NullNetworkPacket()
        if 'transport' not in self.full_packet.keys():
            self.full_packet['transport'] = NullTransportPacket()

    def get_full_packet(self):
        self._add_missed_packets()
        return self.full_packet
