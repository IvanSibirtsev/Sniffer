class PacketFilter:
    def __init__(self, logic_expression, specials):
        self.logic_expression = logic_expression
        if self.logic_expression == 'any':
            self.logic_expression = 'eth and (ipv4 or ipv6) and (tcp or udp)'

        self.specials = specials
        self.flag = True

        self.eth_packet = None
        self.network_packet = None
        self.transport_packet = None
        self.final_packet = None

    def add(self, packet):
        if packet.packet_name in ['eth']:
            self.eth_packet = packet
            for level in [[self.eth_packet]]:
                if self.flag:
                    self.first_check(level)

        if packet.packet_name in ['ipv4', 'ipv6']:
            self.network_packet = packet
            for level in [[self.network_packet],
                          [self.eth_packet, self.network_packet]]:
                if self.flag:
                    self.first_check(level)

        if packet.packet_name in ['tcp', 'udp']:
            self.transport_packet = packet
            for level in [[self.transport_packet],
                          [self.eth_packet, self.transport_packet],
                          [self.network_packet, self.transport_packet],
                          [self.eth_packet, self.network_packet,
                           self.transport_packet]]:
                if self.flag:
                    self.first_check(level)

    def first_check(self, current_packets):
        logic_expr = self.logic_expression

        for name in current_packets:
            if logic_expr.find(name.packet_name) != -1:
                logic_expr = logic_expr.replace(name.packet_name, 'True')

        for name in ['eth', 'ipv4', 'ipv6', 'udp', 'tcp']:
            if logic_expr.find(name) != -1:
                logic_expr = logic_expr.replace(name, 'False')

        if eval(logic_expr) and self.second_check(current_packets):
            self._show_packet(current_packets)
            self.flag = False

    def second_check(self, current_packets):
        if self.specials == 'any':
            return True
        specials = self.specials
        for name in current_packets:
            if name.packet_name in ['ipv4', 'ipv6']:
                if specials.find('src=' + name.s_ip) != -1:
                    specials = specials.replace('src=' + name.s_ip, 'True')
                if specials.find('dst=' + name.d_ip) != -1:
                    specials = specials.replace('dst=' + name.d_ip, 'True')
            if name.packet_name in ['tcp', 'udp']:
                if specials.find('port=' + name.s_port) != -1:
                    specials = specials.replace('port=' + name.s_port, 'True')

        specials = specials.split(' ')
        for i in range(len(specials)):
            if specials[i] not in ['True', 'and', 'or', '(', ')']:
                specials[i] = 'False'
        specials = ' '.join(specials)
        return eval(specials)

    @staticmethod
    def _show_packet(current_packets):
        margin = {'up': '+' + '-' * 92, 'down': '|' + '_' * 92}
        print(margin['up'])
        for packet in current_packets:
            if packet:
                print(packet.to_str())
