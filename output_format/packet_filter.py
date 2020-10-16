class PacketFilter:
    def __init__(self, logic_expression, specials):
        self.logic_expression = logic_expression
        self.specials = specials
        if self.logic_expression == 'any':
            self.logic_expression = 'eth and (ipv4 or ipv6) and (tcp or udp)'

        self.packet = None
        self.eth = None
        self.network = None
        self.transport = None

        self.matching_packets = None

    def _update(self):
        self.eth = self.packet['data_link']
        self.network = self.packet['network']
        self.transport = self.packet['transport']

    def _levels_to_check(self):
        first = [[self.eth]]
        second = [[self.network], [self.eth, self.network]]
        third = [[self.transport], [self.eth, self.transport],
                 [self.network, self.transport],
                 [self.eth, self.network, self.transport]]
        return first, second, third

    def add(self, packet):
        self.packet = packet
        self._update()

    def check(self):
        levels = self._levels_to_check()
        for n in [0, 1, 2]:
            for level in levels[n]:
                first = self._first_check(level)
                second = self._second_check(level)
                if first and second:
                    self.matching_packets = level
                    return True
        return False

    def _first_check(self, current_packets):
        logic_expr = self.logic_expression
        for name in current_packets:
            logic_expr = self.replace(logic_expr, name.packet_name, 'True')

        for name in ['eth', 'ipv4', 'ipv6', 'udp', 'tcp']:
            logic_expr = self.replace(logic_expr, name, 'False')

        return eval(logic_expr)

    def _second_check(self, current_packets):
        spec = self.specials
        if spec == 'any':
            return True
        for name in current_packets:
            if name.level == 'network':
                spec = self.replace(spec, 'src=' + name.s_ip, 'True')
                spec = self.replace(spec, 'dst=' + name.d_ip, 'True')
            if name.level == 'transport':
                spec = self.replace(spec, 'port=' + name.s_port, 'True')

        spec = spec.split(' ')
        for i in range(len(spec)):
            if spec[i] not in ['True', 'and', 'or', '(', ')']:
                spec[i] = 'False'
        spec = ' '.join(spec)

        return eval(spec)

    @staticmethod
    def replace(source, sought, relocatable):
        if source.find(sought) != -1:
            return source.replace(sought, relocatable)
        return source
