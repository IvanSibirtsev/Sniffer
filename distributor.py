from parsers.headers import Ethernet, IPv4, IPv6, UDP, TCP, BinaryData, \
    UnknownPacket


class Distributor:
    def __init__(self, data):
        self.data = data
        self.protocols = {'Start': Ethernet, 2048: IPv4, 34525: IPv6,
                          17: UDP, 6: TCP, 'binary_data': BinaryData}

    def parse(self, protocol):
        try:
            packet = self.protocols[protocol](self.data).parse()
        except KeyError:
            packet = UnknownPacket(protocol, self.data)
        self.data = packet.data
        return packet, packet.data, packet.next_header
