import socket as s
import sys


class Socket:
    ALL_DATA = 65565

    def __init__(self):
        try:
            self.socket = s.socket(s.AF_PACKET, s.SOCK_RAW, s.ntohs(3))
        except AttributeError:
            print('Use Linux.')
            sys.exit()

    def receive_from(self):
        try:
            return self.socket.recvfrom(self.ALL_DATA)[0]
        except PermissionError:
            print('Try sudo.')
            sys.exit()