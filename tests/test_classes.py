class Args:
    def __init__(self, count='1', headers=['any'], special=['any'],
                 report=['any']):
        self.packets_count = count
        self.headers = headers
        self.special = special
        self.binary_mod = False
        self.report = report
        self.filename = 'filename.pcap'


class TestReport:
    def __init__(self, report):
        self.a = None
        self.report = report
        self.s = 0

    def add(self, packet, size):
        self.a = packet
        self.s = size


class TestEthernet:
    def __init__(self):
        self.packet_name = 'eth'

    def to_str(self):
        return self.packet_name


class TestIpv4:
    def __init__(self):
        self.packet_name = 'ipv4'
        self.d_ip = '000.000.000.000'

    def to_str(self):
        return self.packet_name


class TestTCP:
    def __init__(self):
        self.packet_name = 'tcp'
        self.s_port = '80'

    def to_str(self):
        return self.packet_name


class TestSocket:
    ADDRESS = ""

    def __init__(self):
        self.data = b""

    def recvfrom(self, integer):
        return [self.data, self.ADDRESS]
