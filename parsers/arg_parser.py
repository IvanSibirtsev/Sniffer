import argparse
import sys
import re
import socket


LOGIC = {'and', 'or', 'not', '(', ')'}





def parse_args():
    parser = argparse.ArgumentParser(description="intercepts network traffic")
    parser.add_argument('-f', '--file', dest='filename',
                        help="output pcap filename")
    parser.add_argument('-c', '--count', dest='packets_count', default=1,
                        type=int, help='count of packets you want to catch')
    parser.add_argument('-p', '--packets_header', dest='headers',
                        default=['any'], action='extend', nargs='+',
                        help='interface you want to sniff. variants ' +
                             '[eth, ipv4, ipv6, tcp, udp]')
    parser.add_argument('-s', '--special', dest='special', default=['any'],
                        action='extend', nargs='+',
                        help='more detailed information you want to sniff. ' +
                             'variants [host, src, dst, port]')
    parser.add_argument('-r', '--report', dest='report', default=['any'],
                        action='extend', nargs='+',
                        help='print report. variants [ip, count, bytes]')
    parser.add_argument('-b', '--binary', dest='binary_mod',
                        action='store_true')
    args = Args(parser.parse_args())
    return args


class Args:
    def __init__(self, args):
        self.filename = args.filename
        self.packets_count = ArgCount(args).count
        self.headers = ArgHeaders(args).headers
        self.special = ArgSpecial(args).special
        self.report = ArgReport(args).report


class ArgCount:
    def __init__(self, args):
        self.count = args.packets_count
        self.check()
        if not args.filename and self.count == 1:
            self.count = float('inf')

    def check(self):
        try:
            count = int(self.count)
        except ValueError:
            print('--count must be a number.')
            sys.exit()
        if count < 0:
            print('--count must be a positive number.')
            sys.exit()


class ArgHeaders:
    def __init__(self, args):
        self.args = args
        self.check()
        self.headers = self.parse_interfaces(args.headers)

    def check(self):
        interfaces = self.parse_interfaces(self.args.headers)
        interfaces = interfaces.split(' ')
        language = {'any', 'eth', 'ipv4', 'ipv6', 'tcp', 'udp'}
        language |= LOGIC
        for interface in interfaces:
            if interface in language:
                pass
            else:
                print(f'Unknown packet header "{interface}". ' +
                      'Try "sudo python3 sniffer.py -h"')
                sys.exit()

    @staticmethod
    def parse_interfaces(args):
        interfaces = ' '.join(args)
        interfaces = interfaces.replace('any ', '')
        if len(interfaces) <= 1:
            interfaces = 'any'
        if interfaces.count('(') != interfaces.count(')'):
            print('close bracket.')
            sys.exit()
        for replace in [('  ', ' '), ('(', '( '), (')', ' )'), ('  ', ' ')]:
            interfaces = interfaces.replace(replace[0], replace[1])
        return interfaces


class ArgSpecial:
    def __init__(self, args):
        self.special = ArgHeaders.parse_interfaces(args.special)
        self.check()
        self.parse_special()

    def check(self):
        special = self.special.split(' ')
        language = {'any', 'host', 'src', 'dst', 'port'}
        language |= LOGIC
        ip_regex = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        for spec in special:
            result = re.match(ip_regex, spec)
            if not (result or spec.isdigit() or spec in language):
                print(f'Unknown "{spec}". Try "sudo python3 sniffer.py -h"')
                sys.exit()

    def parse_special(self):
        if self.special.find('host') != -1:
            host = socket.gethostbyaddr(socket.gethostname())[2][0]
            self.special = self.special.replace('host', 'host ' + host)
        for name in ['host', 'src', 'dst', 'port']:
            if self.special.find(name) != -1:
                self.special = self.special.replace(name + ' ', name + '=')
        self.parse_host()
        self.special = ArgHeaders.parse_interfaces(self.special)

    def parse_host(self):
        self.special = self.special.split(' ')
        for i in range(len(self.special)):
            if self.special[i].find('host') != -1:
                host = self.special[i]
                index = host.index('=')
                ip = host[index + 1:]
                self.special[i] = f'( src={ip} or dst={ip} )'


class ArgReport:
    def __init__(self, args):
        self.report = args.report
        self.check()

    def check(self):
        for element in self.report:
            if element not in ['any', 'ip', 'count', 'bytes']:
                print(f'Unknown "{element}". Try "sudo python3 sniffer.py -h"')
                sys.exit()

    def parse_report(self):
        if 'any' in self.report:
            self.report = self.report[1:]
