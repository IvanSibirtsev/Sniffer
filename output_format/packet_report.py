from prettytable import PrettyTable


class PacketReport:
    def __init__(self, report_type):
        self._sum = 0
        self.report_type = ['ip', 'count', 'bytes'] if report_type == ['any'] \
            else report_type
        self._packet = None
        self._dictionary = {}
        self._ip_list = []

    def add(self, packet, size):
        packet_name = packet.packet_name
        if packet_name in ['eth', 'tcp', 'udp']:
            return
        if packet_name in ['ipv4', 'ipv6']:
            self._update_dictionary(packet.d_ip, size)
        self._update_sum(size)

    def _update_dictionary(self, ip, size):
        if self._dictionary.get(ip):
            tmp = self._dictionary.get(ip)
            self._dictionary[ip] = [tmp[0] + 1, tmp[1] + size]
        else:
            self._dictionary[ip] = [1, size]
            self._ip_list.append(ip)

    def _update_sum(self, size):
        self._sum += size

    def show_report(self):
        self._make_table()

    def _show_size(self):
        string = f'All packages size - {self._sum} bytes.'
        return string

    def _make_table(self):
        table = PrettyTable(self.report_type)
        for ip in self._ip_list:
            req_count, size = self._dictionary[ip]
            dictionary = {'ip': ip, 'count': req_count, 'bytes': size}
            row = [dictionary[report_type] for report_type in self.report_type]
            table.add_row(row)
        print(table)
        print(self._show_size())
