from prettytable import PrettyTable


class PacketReport:
    def __init__(self, report_type):
        self._sum = 0
        self.report_type = report_type
        self._packet = None
        self._dictionary = {}
        self._ip_list = []

        self.table = None

    def add(self, full_packet):
        packet = full_packet.full_packet
        self._update_dictionary(packet['network'].d_ip,
                                full_packet.packet_size)
        self._update_sum(full_packet.packet_size)

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
        self.table = PrettyTable(self.report_type)
        for ip in self._ip_list:
            req_count, size = self._dictionary[ip]
            dictionary = {'ip': ip, 'count': req_count, 'bytes': size}
            row = [dictionary[report_type] for report_type in self.report_type]
            self.table.add_row(row)
        str(self.table) + '\n' + self._show_size()
