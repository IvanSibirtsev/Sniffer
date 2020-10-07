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
                        help='count of packets you want to catch')
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
    check_count(parser.parse_args())
    check_interfaces(parser.parse_args())
    check_special(parser.parse_args())
    check_report(parser.parse_args())
    return parser.parse_args()


def check_count(args):
    try:
        count = int(args.packets_count)
    except ValueError:
        print('--count must be a number.')
        sys.exit()
    if count < 0:
        print('--count must be a positive number.')
        sys.exit()


def check_interfaces(args):
    interfaces = parse_interfaces(args.headers)
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


def check_special(args):
    specials = parse_interfaces(args.special)
    specials = specials.split(' ')
    language = {'any', 'host', 'src', 'dst', 'port'}
    language |= LOGIC
    ip_regex = re.compile('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    for spec in specials:
        result = re.match(ip_regex, spec)
        if not (result or spec.isdigit() or spec in language):
            print(f'Unknown "{spec}". Try "sudo python3 sniffer.py -h"')
            sys.exit()


def check_report(args):
    for element in args.report:
        if element not in ['any', 'ip', 'count', 'bytes']:
            print(f'Unknown "{element}". Try "sudo python3 sniffer.py -h"')
            sys.exit()


def keys_parser(args):
    logic_expression = parse_interfaces(args.headers)
    specials = parse_special(args.special)
    report = parse_report(args.report)
    show_bytes = args.binary_mod
    return logic_expression, specials, report, show_bytes


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


def parse_host(special):
    special = special.split(' ')
    for i in range(len(special)):
        if special[i].find('host') != -1:
            host = special[i]
            index = host.index('=')
            ip = host[index + 1:]
            special[i] = f'( src={ip} or dst={ip} )'
    return special


def parse_special(special):
    special = parse_interfaces(special)
    if special.find('host') != -1:
        host = socket.gethostbyaddr(socket.gethostname())[2][0]
        special = special.replace('host', 'host ' + host)
    for name in ['host', 'src', 'dst', 'port']:
        if special.find(name) != -1:
            special = special.replace(name + ' ', name + '=')
    special = parse_host(special)
    special = parse_interfaces(special)
    return special


def parse_report(report):
    if len(report) == 1:
        return report
    if 'any' in report:
        report = report[1:]
        return report
