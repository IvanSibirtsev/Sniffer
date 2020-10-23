import socket
import unittest
from prettytable import PrettyTable
import os
import io
import sys

import tests.test_classes as test
import sniffer
from packets import headers
from utils import socketWrapper
from output_format.filters import packet_filter as pf
from packets import full_packet
from output_format import console


class TestPcap(unittest.TestCase):
    def setUp(self):
        self.old_stdout = sys.stdout
        sys.stdout = io.StringIO()

    def test_pcap_file_exists_end_close(self):
        args = test.Args()
        t_socket = test.TestSocket()
        sniffer.Sniffer(t_socket, args).start_sniff()
        path = os.path.join('pcap', 'test.pcap')
        self.assertEqual(os.path.exists(path), True)
        sys.stdout = self.old_stdout
        os.remove(path)


class TestParsersTCP(unittest.TestCase):
    def test_ethernet(self):
        ethernet = headers.Ethernet(test.raw_data_1).parse()
        right_header = ('08:00:27:54:ec:cd', '52:54:00:12:35:02', 2048)
        ethernet_header = ethernet.get_all_ethernet_information()
        self.assertEqual(ethernet_header, right_header)
        return ethernet.data

    def test_ipv4(self):
        data = self.test_ethernet()
        ipv4 = headers.IPv4(data).parse()
        right_header = (4, 20, 0, 40, 65058, 2, 0, 64, 6, 54690,
                        '10.0.2.15', '92.122.254.129')
        ipv4_header = ipv4.get_all_ipv4_information()
        self.assertEqual(ipv4_header, right_header)
        return ipv4.data

    def test_tcp(self):
        data = self.test_ipv4()
        tcp = headers.TCP(data).parse()
        tcp_header = tcp.get_all_tcp_information()
        right_header = ('55702', '443', 1211858345, 278278377,
                        63900, 26405, 0, [0, 1, 0, 0, 0, 0])
        self.assertEqual(tcp_header, right_header)


class TestParsersToUDP(unittest.TestCase):
    @staticmethod
    def make_udp_data():
        data = test.raw_data_2
        for parser in [headers.Ethernet, headers.IPv4]:
            data = parser(data).parse().data
        return data

    def test_udp(self):
        data = self.make_udp_data()
        udp = headers.UDP(data).parse()
        udp_header = udp.get_all_udp_information()
        right_header = ('39676', '53', 54, 65149)
        self.assertEqual(udp_header, right_header)


class TestSocketWrapper(unittest.TestCase):
    def test_exceptions(self):
        if os.getuid() != 0:
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            with self.assertRaises(SystemExit):
                with self.assertRaises(PermissionError):
                    socketWrapper.Socket()
            sys.stdout = old_stdout
            output = buffer.getvalue()
            self.assertEqual(output, 'Try sudo.\n')


class TestSniffer(unittest.TestCase):
    def test_console_mod(self):
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()

        test_socket = test.TestSocket()
        test_args = test.Args(headers='eth', filename='')
        console_sniffer = sniffer.Sniffer(test_socket, test_args)
        console_sniffer.start_sniff()
        right = '+' + '-' * 92 + '\n| Ethernet:\n' + headers.TAB_1
        right += ('Destination MAC: 08:00:27:54:ec:cd,' +
                  ' Source MAC: 52:54:00:12:35:02, Protocol: 2048.\n')
        sys.stdout = old_stdout
        output = buffer.getvalue()
        self.assertEqual(output, right)


class TestPacketFilter(unittest.TestCase):
    @staticmethod
    def create_and_add_packet(test_full_packet, created_packet_type):
        added_packet = created_packet_type()
        test_full_packet.add_packet(added_packet)

    def test_any(self):
        margin = '+' + '-' * 92
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()

        args = test.Args()
        test_console = console.Console(args)
        full_packet_test = full_packet.FullPacket(57)
        self.create_and_add_packet(full_packet_test, test.TestEthernet)
        self.create_and_add_packet(full_packet_test, test.TestIpv4)
        self.create_and_add_packet(full_packet_test, test.TestTCP)
        test_console.print(full_packet_test)
        right = margin + '\n' + 'eth\n' + 'ipv4\n' + 'tcp\n'

        sys.stdout = old_stdout
        output = buffer.getvalue()
        self.assertEqual(output, right)


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
        first_output = ('Unknown packets header "tcd". ' +
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
