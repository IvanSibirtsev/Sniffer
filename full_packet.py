

class FullPacket:
    def __init__(self, size):
        self.full_packet = {}
        self.packet_size = size

    def add_packet(self, packet):
        if packet.level == 'unknown':
            pass
        self.full_packet[packet.level] = packet
