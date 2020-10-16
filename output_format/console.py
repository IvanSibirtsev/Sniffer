from output_format.packet_filter import PacketFilter
from output_format.packet_report import PacketReport


class Console:
    margin = '+' + '-' * 92

    def __init__(self, args):
        self.args = args
        self.printed = False
        self.packet_report = PacketReport(self.args.report)
        self.packet_filter = PacketFilter(self.args.headers,
                                          self.args.specials)

    def main_method(self, full_packet):
        self.packet_filter.add(full_packet.get_full_packet())
        self.packet_report.add(full_packet)
        if self.packet_filter.check():
            self.printed = True
            self.console_output(self.packet_filter.matching_packets)
        else:
            self.printed = False

    def console_output(self, packets):
        self.printed = True
        print(self.margin)
        for packet in packets:
            if packet:
                print(packet.to_str())
