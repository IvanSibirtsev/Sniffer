import socket
import unittest
from prettytable import PrettyTable
import os
import io
import sys

# sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.path.pardir))

import sniffer
import distributor as h
from output_format.filters import packet_report as pr, packet_filter as pf
from tests import test_classes as test


class TestPcap(unittest.TestCase):
    def test_pcap_file_exists_end_close(self):
        dictionary = {0: test.raw_data_1}
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        self.pcap_maker = sniffer.pcap_mod('test_pcap.pcap', dictionary, 1)
        path = os.path.join('pcap', 'test_pcap.pcap')
        self.assertEqual(os.path.exists(path), True)
        sys.stdout = old_stdout
        os.remove(path)


class TestParsersTCP(unittest.TestCase):
    def test_ethernet(self):
        self.ethernet, self.data = hp.parse_ethernet(test.raw_data_1)[0:2]
        self.right_header = ('08:00:27:54:ec:cd', '52:54:00:12:35:02', 2048)
        self.ethernet_header = self.ethernet.get_all_ethernet_information()
        self.assertEqual(self.ethernet_header, self.right_header)
        return self.data

    def test_ipv4(self):
        self.data = self.test_ethernet()
        self.ipv4, self.data = hp.parse_ipv4(self.data)[0:2]
        self.right_header = (4, 20, 0, 40, 65058, 2, 0, 64, 6, 54690,
                             '10.0.2.15', '92.122.254.129')
        self.ipv4_header = self.ipv4.get_all_ipv4_information()
        self.assertEqual(self.ipv4_header, self.right_header)
        return self.data

    def test_tcp(self):
        self.data = self.test_ipv4()
        self.tcp = hp.parse_tcp(self.data)[0]
        self.tcp_header = self.tcp.get_all_tcp_information()
        self.right_header = ('55702', '443', 1211858345, 278278377,
                             63900, 26405, 0, [0, 1, 0, 0, 0, 0])
        self.assertEqual(self.tcp_header, self.right_header)


class TestParsersToUDP(unittest.TestCase):
    def make_udp_data(self):
        self.data = test.raw_data_2
        for parser in [hp.parse_ethernet, hp.parse_ipv4]:
            self.data = parser(self.data)[1]
        return self.data

    def test_udp(self):
        self.data = self.make_udp_data()
        self.udp = hp.parse_udp(self.data)[0]
        self.udp_header = self.udp.get_all_udp_information()
        self.right_header = ('39676', '53', 54, 65149)
        self.assertEqual(self.udp_header, self.right_header)


class TestSniffer(unittest.TestCase):
    def test_exception(self):
        if os.getuid() != 0:
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            sniffer.sniffer('')
            sys.stdout = old_stdout
            output = buffer.getvalue()
            self.assertEqual(output, 'Try sudo\n')

    def test_console_mod(self):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        test_report = test.TestReport(['any'])
        test_socket = test.TestSocket()
        test_args = test.Args(headers='eth')
        sniffer.console_mod(test_socket, test_args)
        right = '+' + '-' * 92 + '\n| Ethernet:\n' + h.TAB_1
        right += ('Destination MAC: 08:00:27:54:ec:cd,' +
                  ' Source MAC: 52:54:00:12:35:02, Protocol: 2048.\n')
        sys.stdout = old_stdout
        output = buffer.getvalue()
        self.assertEqual(output, right)

    def test_console(self):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        test_socket = test.TestSocket()
        test_args = test.Args()
        sniffer.console_mod(test_socket, test_args)
        sys.stdout = old_stdout
        output = buffer.getvalue()
        right = ''
        self.assertEqual(output, right)


class TestCUI(unittest.TestCase):
    def test_ethernet(self):
        s, d = b'\xff\xff\xff\xff\xff\xff', b'\x00\x00\x00\x00\x00\x00'
        ethernet_inf = h.Ethernet(s, d, 0)
        s_mac, d_mac = 'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'
        right = '| Ethernet:\n' + h.TAB_1
        right += f'Destination MAC: {s_mac}, Source MAC: {d_mac}, Protocol: 0.'
        self.assertEqual(ethernet_inf.to_str(), right)

    def test_ipv4(self):
        s, d = b'S\xaa\x06L', b'S\xaa\x06L'  # StackOverFlow
        ipv4_inf = hp.IPv4(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, s, d)
        right = '| IPv4:\n' + h.TAB_1
        right += ('Version: 1, Header Length: 1, ToS/DSCP: 1, ' +
                  'Total Length: 1, Identificator: 1.\n' + h.TAB_1)
        right += ('Flags: 1, Fragmentation Offset: 1, TTL: 1, ' +
                  'Protocol: 1, Header Checksum: 1.\n') + h.TAB_1
        right += 'Source IP: 83.170.6.76, Destination IP: 83.170.6.76.'
        self.assertEqual(ipv4_inf.to_str(), right)

    def test_tcp(self):
        tcp_inf = h.TCP(1, 1, 1, 1, 1, 1, 1, [1, 1, 1, 1, 1, 1])
        right = '| TCP Segment:\n' + h.TAB_1
        right += f'Source Port: 1, Destination Port: 1\n' + h.TAB_1
        right += 'Sequence: 1, Acknowledgment: 1, Window Size: 1\n'
        right += h.TAB_1 + 'Checksum: 1, Urgent Point: 1.\n'
        right += h.TAB_1 + 'Flags:\n'
        right += h.TAB_2 + 'URG: 1, ACK: 1, PSH: 1\n'
        right += h.TAB_2 + 'RST: 1, SYN: 1, FIN: 1'
        self.assertEqual(tcp_inf.to_str(), right)

    def test_udp(self):
        udp_inf = h.UDP(1, 1, 1, 1)
        right = '| UDP Segment:\n' + h.TAB_1
        right += 'Source Port: 1, Destination Port: 1.\n' + h.TAB_1
        right += 'Length: 1, Checksum: 1.'
        self.assertEqual(udp_inf.to_str(), right)


class TestPacketFilter(unittest.TestCase):
    def test_any(self):
        margin = '+' + '-' * 92
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()

        packet = test.TestEthernet()
        self.packet_filter = pf.PacketFilter('any', 'any')
        self.packet_filter.add(packet)
        packet = test.TestIpv4()
        self.packet_filter.add(packet)
        packet = test.TestTCP()

        self.packet_filter.add(packet)
        right = margin + '\n' + 'eth\n' + 'ipv4\n' + 'tcp\n'

        self.packet_filter = pf.PacketFilter('eth and ipv4', 'any')
        packet = test.TestEthernet()
        self.packet_filter.add(packet)
        packet = test.TestIpv4()
        self.packet_filter.add(packet)
        packet = test.TestTCP()
        self.packet_filter.add(packet)
        right += margin + '\n' + 'eth\n' + 'ipv4\n'

        self.packet_filter = pf.PacketFilter('tcp', 'port=80')
        packet = test.TestTCP()
        self.packet_filter.add(packet)
        right += margin + '\n' + 'tcp\n'
        sys.stdout = old_stdout
        output = buffer.getvalue()
        self.assertEqual(output, right)


class TestUnknown(unittest.TestCase):
    def test_determine(self):
        self.output = hp.parser_determine('no', 1544)
        self.assertEqual(self.output[2], 'End')


class TestArgParse(unittest.TestCase):
    def test_count_positive(self):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        args = test.Args(count='-20')
        right = '--count must be a positive number.\n'
        with self.assertRaises(SystemExit):
            ap.check_count(args)
        sys.stdout = old_stdout
        output = buffer.getvalue()
        self.assertEqual(output, right)

    def test_count_no_number(self):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        args = test.Args(count='a')
        right = '--count must be a number.\n'
        with self.assertRaises(SystemExit):
            ap.check_count(args)
        sys.stdout = old_stdout
        output = buffer.getvalue()
        self.assertEqual(output, right)

    def test_check_special(self):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        args = test.Args(special=['por', '80', 'or', 'port', '443'])
        right = 'Unknown "por". Try "sudo python3 sniffer.py -h"\n'
        with self.assertRaises(SystemExit):
            ap.check_special(args)
        sys.stdout = old_stdout
        output = buffer.getvalue()
        self.assertEqual(output, right)

    def test_check_report(self):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        args = ['ip', 'bytes', 'abc']
        report = test.TestReport(args)
        with self.assertRaises(SystemExit):
            ap.check_report(report)
        sys.stdout = old_stdout
        output = buffer.getvalue()
        right = 'Unknown "abc". Try "sudo python3 sniffer.py -h"\n'
        self.assertEqual(output, right)

    def test_parse_report(self):
        report = ['any']
        report = ap.parse_report(report)
        self.assertEqual(report, ['any'])

        report = ['any', 'ip', 'bytes']
        report = ap.parse_report(report)
        self.assertEqual(report, ['ip', 'bytes'])

    def test_parse_special(self):
        host = socket.gethostbyaddr(socket.gethostname())[2][0]
        args = test.Args(special=['port', '80', 'and', 'host'])
        special = ap.parse_special(args.special)
        right = f'port=80 and ( src={host} or dst={host} )'
        self.assertEqual(special, right)

    def test_parse_interfaces(self):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        args = test.Args(headers=['any', 'ipv4', 'and', 'tcd'])
        first_output = ('Unknown packet header "tcd". ' +
                        'Try "sudo python3 sniffer.py -h"\n')
        with self.assertRaises(SystemExit):
            ap.check_interfaces(args)
        args = test.Args(headers=['ipv4', 'and', '(', 'tcp', 'or', 'udp'])
        right_output = first_output + 'close bracket.\n'
        with self.assertRaises(SystemExit):
            ap.check_interfaces(args)
        args = test.Args()
        none = ap.check_interfaces(args)
        self.assertEqual(none, None)
        sys.stdout = old_stdout
        output = buffer.getvalue()
        self.assertEqual(output, right_output)

    def test_key_parser(self):
        args = test.Args(report=['any', 'ip', 'count'])
        args = ap.keys_parser(args)
        right = ('any', 'any', ['ip', 'count'], False)
        self.assertEqual(args, right)


class TestPacketReport(unittest.TestCase):
    def test_report(self):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()

        packet = test.TestIpv4()
        packet_report = pr.PacketReport(['any'])
        packet_report.add(packet, 100)
        packet_report.add(packet, 200)
        packet_report.show_report()

        right = PrettyTable(['ip', 'count', 'bytes'])
        right.add_row(['000.000.000.000', 2, 300])
        sys.stdout = old_stdout
        output = buffer.getvalue()
        dop_inf = '\nAll packages size - 300 bytes.\n'
        self.assertEqual(output, str(right) + dop_inf)


if __name__ == '__main__':
    unittest.main()
