class FormatTraceData():
    def __init__(self, data, num_fragments, offset):
        self.data = data
        self.num_fragments = num_fragments
        self.offset = offset

    def print_results(self):
        self.print_header()
        self.print_IP_details()

    def print_header(self):
        print(f"{'Row':<5} {'Components':<60} {'Details'}")
        print("=" * 90)

    def print_row(self, row_num, component, details, divider=True):
        print(f"{row_num:<5} {component:<60} {details}")
        if divider:
            print("-" * 90)

    def print_IP_details(self):
        self.print_row("1","The IP address of the source node (R1)", self.data.endpoints.source_ip)
        self.print_row("2","The IP address of ultimate destination node (R1)", self.data.endpoints.dest_ip)
        self.print_row("3","The IP addresses of the intermediate destination nodes (R1)", self.data.interm_nodes[0], divider=False)
        self.print_interm_nodes()
        self.print_row("4", "The correct order of the intermediate destination nodes (R1)",self.data.interm_nodes[0], divider=False)
        self.print_interm_nodes()
        self.print_row("5", "The values in the protocol fields of IP headers (R1)", self.format_protocols())
        self.print_row("6", "Number of fragments created from the original datagram (R1)", self.num_fragments)
        self.print_row("7", "The offset of the last fragment (R1)", self.offset)
        self.print_row("8", "The avg RTT to ultimate destination node (R1)", self.format_time_value(self.data.dest_rtt[0]),divider=False)
        self.print_interm_rtts()
        self.print_row("9", "The std deviation of RTT to ultimate destination node (R1)", self.format_time_value(self.data.dest_rtt[1]),divider=False)
        self.print_interm_rtts(avs=False)
        self.print_row("10", "The number of probes per TTL (R2)", self.format_TTL(1), divider=False)
        self.print_ttl_probe_nums()
#        print(answer_11)

    def print_TTLS(self):
#        print(f"{'TTL':<3} {'Routers':>16}")
        for ttl in sorted(self.data.data.keys()):
            print(f"TTL = {ttl:>2}: {', '.join(map(str, self.data.data[ttl]))}")
#        for ttl in sorted(self.data.endpoints_data.keys()):
#            print(f"\n{ttl:<3}: {', '.join(map(str, self.data.endpoints_data[ttl]))}")


    def format_TTL(self, ttl, endpoints=False):
        if not endpoints:
            return f"TTL {ttl:>2}: {len(self.data.data[ttl])}"
        else:
            return f"TTL {ttl:>2}: {len(self.data.endpoints_data[ttl])}"
    
    def print_ttl_probe_nums(self):
        for ttl in sorted(self.data.data.keys()):
            if ttl != 1:
                self.print_row("","",self.format_TTL(ttl),divider=False)

        for ttl in sorted(self.data.endpoints_data.keys()):
            if ttl != 1:
                self.print_row("","",self.format_TTL(ttl,endpoints=True),divider=False)

#    def format_time_value(self,value):
#        if value is not None:
#            return f"{value:.5f} ms"

    def format_time_value(self,value):
#        if value >= 600:
#            value -= 600
        if value is not None:
            return f"{value:.5f} ms"

        
    def print_interm_nodes(self):
        interm_nodes = self.data.interm_nodes[1:]
        for ip in interm_nodes:
            self.print_row("","",ip,divider=False)
        print("-" * 90)

    def print_interm_rtts(self,avs=True):
        for ip, values in self.data.avg_rtts.items():
            if not avs:
                self.print_row("",f"The stdev of RTT b/tn {self.data.endpoints.source_ip} and {ip} (R1)",self.format_time_value(values[1]),divider=False)
            else:
                self.print_row("",f"The avg RTT between {self.data.endpoints.source_ip} and {ip} (R1)",self.format_time_value(values[0]),divider=False)
        print("-" * 90)

    def format_protocols(self):
        return ", ".join(self.data.protocols)

