import math

class Endpoints:
    def __init__(self, packet):
        self.source_ip = packet.ip_header.source_ip
        self.dest_ip = packet.ip_header.dest_ip
        self.source_port = packet.protocol_header.source_port # connection always initialized with UDP protocol 
        self.dest_port = packet.protocol_header.dest_port

    def __str__(self):
         return (f"The IP address of the source node: {self.source_ip}\n"
                f"The IP address of ultimate destination node: {self.dest_ip}")

class Connection:
    def __init__(self, udp_packet, icmp_packet=None, rtt=None, total_rtt=None):
        self.udp_packet = udp_packet
        self.endpoints = Endpoints(udp_packet) # original data gram source and dest IP
        self.ttl = udp_packet.ip_header.ttl
        self.icmp_packet = icmp_packet
        self.rtt = rtt
        self.total_rtt = total_rtt
        self.fragments = [] # list of fragments from this connection matched by IP ID number
    
    def set_icmp_packet(self, packet):
        self.icmp_packet = packet 
        self.set_rtt()

    def set_rtt(self):
        self.rtt = abs(self.icmp_packet.timestamp - self.udp_packet.timestamp)

    def set_fragment_list(self, packet_list):
        self.fragments = packet_list

    def get_fragmment_len(self):
        return len(self.fragments)

    def get_last_frag_offset(self):
        last_fragment = self.fragments[-1]
        offset = last_fragment.get_frag_offset() * 8
        return offset

    def print_fragments(self):
        print("\n---------- Fragmented Packets ------")
        for packet in self.fragments:
            out = str(packet)
#            print(f"{packet.ip_header}\n{packet.protocol_header}")
            print(out)

    def __str__(self):
        out = str(self.udp_packet)
#        out+=f"----------------"
        if self.icmp_packet is not None:
            out+= str(self.icmp_packet)
        return out
#        return (f"{self.icmp_packet.ip_header.source_ip:<16}")


class ConnectionsData:
    def __init__(self, icmp_added=False, udp_added=False):
        self.data = {}             # maps source ports to corresponding UDP/ICMP messages
        self.endpoints_data = {}   # original source and ultimate destination UDP/ICMP messages
        self.fragments = {}        # dictionary of all fragments in trace
        self.protocols = []
        self.num_fragments = 0
        self.icmp_added = icmp_added
        self.udp_added = udp_added



    def pretty_print(self):
        for ttl, connec in self.data.items():
            out = "------------ Connection ----------\n"
            out+= "UDP PACKET -----------------------\n"
            out+= "Source Port: {connec.udp_packet.source_port}\n"
            out+= "Dest Port  : {connec.udp_pacet.dest_port}}\n"
            out+= str(connec.udp_packet.ip_header)



    def update_fragments(self, packet):
        """
        Maps IP Header Identification for UDP packet to list of corresponding fragments
        """
        ip_id = packet.get_ip_id()

        # If ID in fragments, then add current packet to ID fragment entry
        if ip_id in self.fragments:
            self.fragments[ip_id].append(packet)

        # Otherwise, check if current packet is fragment, and create new entry if it is
        elif packet.get_MF_value() == 1 or packet.get_frag_offset() > 0:
            self.fragments[ip_id] = [packet]

    def add_connection(self, packet, source_port):
        """
        Create new data entry with UDP source port and add UDP packet. 
        """
        if packet.is_udp():
            self.update_protocols(17)
            self.data[source_port] = Connection(packet)

    def update_connections(self, packet, source_port):
        """
        Add ICMP response to corresponding UDP probe by matching source port.
        """
        if packet.is_icmp():
            self.update_protocols(1)
            connection = self.data[source_port]
            connection.set_icmp_packet(packet)

    def add_or_update_connections(self, packet):
        if packet.is_udp():
            self.update_fragments(packet)
        source_port = packet.get_source_port() # returns original datagram source port if icmp packet 
        if source_port not in self.data:
            self.add_connection(packet, source_port)
        else:
            self.update_connections(packet, source_port)

    def update_protocols(self, i):
        if i == 1 and not self.icmp_added:
            self.protocols.append("1: ICMP")
            self.icmp_added=True
        elif i == 17 and not self.udp_added:
            self.protocols.append("17: UDP")
            self.udp_added=True 
    
    def print_fragments(self):
       for ip_id, packets in self.fragments.items():
        print(f"IP ID {ip_id}: {[p.get_frag_offset() for p in packets]}")  # Check offsets

    def get_fragment_stats(self):
        for ip_id,packets in self.fragments.items():
            num_fragments = len(packets)
            offset = packets[-1].get_frag_offset() * 8
            return num_fragments, offset


    def filter_connections(self):
        """
        Removes all entries with no ICMP response and separates intermediate and endpoint data.
        """
        self.data = {
            key: value for key, value in self.data.items() if value.icmp_packet is not None
        }

        # Ultimate destination packets
        self.endpoints_data = {
            key: value for key, value in self.data.items()
            if value.icmp_packet.ip_header.source_ip == value.endpoints.dest_ip
        }

        # Intermediate 
        self.data = {
            key: value for key, value in self.data.items() 
            if value.icmp_packet.ip_header.source_ip != value.endpoints.dest_ip
        }

        # Add fragments to connections: match UDP source port in fragment list to data entry
        remaining_fragments = {} 
        for ip_id, packets in self.fragments.items():
            matched = False
            for packet in packets:
                source_port = packet.get_source_port() 
                if source_port in self.data:
                    self.data[source_port].set_fragment_list(packets) # add list of fragments to matching intermediate data entry 
                    matched = True
                elif source_port in self.endpoints_data:
                    self.endpoints_data[source_port].set_fragment_list(packets) # add list to matching endpoint data entry 
                    matched = True
            if not matched:
                remaining_fragments[ip_id] = packets  # Keep unmatched fragments
        self.fragments = remaining_fragments 


class TracerouteData:
    def __init__(self, connections, endpoints=None, interm_nodes=None, avg_rtts=None, dest_rtt=None):
        self.data = {}
        self.endpoints_data = {}
        self.protocols = connections.protocols
        self.connections = connections.data
        self.endpoint_connecs = connections.endpoints_data
        self.endpoints = endpoints # soruce and dest IP of original Datagram
        self.interm_nodes = interm_nodes
        self.avg_rtts = avg_rtts
        self.dest_rtt = dest_rtt


    def print_connections(self):
        for ttl, connecs in self.data.items():
            print(f"==== TTL: {ttl}")
            i = 1
            for connec in connecs:
                print("------------------------------------------------------------------------------------------------")
                print(connec)
#                print(f"UDP Probe: {i}  | Router IP: {connec.icmp_packet.ip_header.source_ip:<16}| RTT: {connec.rtt:.6f}")
                i+=1
#                if self.connec.fragments:
#                    connec.print_fragments()
            print()

    def get_traceroute_data(self):
        """
        Updates the traceroute_data dictionary where each key is the TTL value from the original datagram and
        the values are a list of probes sent with that TTL. 
        """
        for connec in self.connections.values():
            ttl = connec.udp_packet.ip_header.ttl
            if ttl not in self.data:
                self.data[ttl] = []
            self.data[ttl].append(connec)

        # Note to self: only need this for part 2 
        for connec in self.endpoint_connecs.values():
            ttl = connec.udp_packet.ip_header.ttl
            if ttl not in self.endpoints_data:
                self.endpoints_data[ttl] = []
            self.endpoints_data[ttl].append(connec)

        self.set_endpoints()
        self.set_interm_nodes()
        self.set_avg_rtts()
        self.get_dest_rtts()
#        self.print_connections()

    def set_endpoints(self):
        if 1 in self.data and self.data[1]:
            self.endpoints = self.data[1][0].endpoints # original datagram: 1st UDP packet,TTL=1
        else:
            raise ValueError("Traceroute data incomplete: no data for TTL = 1")
        
    def set_interm_nodes(self):
        """
        Removes any duplicate router IP's present in cases where multiple UDP packets were sent with
        the same TTL and followed the same route. 
        """
        router_ips = self.get_all_router_ips()
        self.interm_nodes = list(dict.fromkeys(router_ips))  # removes duplicates
        
    def get_TTL_router_ips(self, ttl):
        """
        Returns a list of the ICMP source IP from the traceroute data for TTL = ttl. 
        """
        if ttl not in self.data or not self.data[ttl]:
            raise ValueError(f"Traceroute data is empty at TTL = {ttl}")
        return [connection.icmp_packet.ip_header.source_ip for connection in self.data[ttl]]


    def get_all_router_ips(self):
        """
        Returns list of all intermediate nodes (router IPs) for all TTL values.
        """
        all_router_ips = []
        for ttl in sorted(self.data.keys()):
            all_router_ips.extend(self.get_TTL_router_ips(ttl))
        return all_router_ips

    def get_intermitt_rtts(self):
        """
        Returns a mapping of intermediate router IP's to its corresponding list of RTT values,
        including fragment RTTs where applicable.
        """
        if not self.interm_nodes:
            raise ValueError("Intermediate nodes list is empty.")

        router_rtts = {router: [] for router in self.interm_nodes}

        for ttl, connections in self.data.items():
            for connection in connections:
                router_ip = connection.icmp_packet.ip_header.source_ip
                if router_ip in router_rtts:
                    # Add the RTT for the main connection
                    router_rtts[router_ip].append(connection.rtt)

                    # Handle fragments, if any
                    if connection.fragments:
       #                 print("HANDLING FRAGMENTS")
                        for fragment in connection.fragments:
                            # Skip the original UDP packet (already included in RTT)
                            if fragment.ip_header.source_ip != connection.icmp_packet.ip_header.source_ip:
                                fragment_rtt = abs(
                                    connection.icmp_packet.timestamp - fragment.timestamp
                                )
                                router_rtts[router_ip].append(fragment_rtt)

        return router_rtts



    def old_get_intermitt_rtts(self):
        """
        Returns a mapping of intermediate router IP's to its corresponding list of RTT values
        """
        if not self.interm_nodes:
            raise ValueError("Intermediate nodes list is empty.")

        router_rtts = {router: [] for router in self.interm_nodes}

        for ttl, connections in self.data.items():
            for connection in connections:
                router_ip = connection.icmp_packet.ip_header.source_ip
                if router_ip in router_rtts:
                    router_rtts[router_ip].append(connection.rtt)
        return router_rtts

    def get_dest_rtts(self):
        """
        Takes average and stddev of all RTT values for all routes to the ultimate destination node,
        including RTTs for fragments where applicable.
        """
        dest_rtts = []

        for connec in self.endpoint_connecs.values():
            # Add the main connection RTT
            dest_rtts.append(connec.rtt)

            # Add fragment RTTs, if any
            if connec.fragments:
                for fragment in connec.fragments:
                    if fragment.ip_header.source_ip != connec.icmp_packet.ip_header.source_ip:
                        fragment_rtt = abs(
                            connec.icmp_packet.timestamp - fragment.timestamp
                        )
                        dest_rtts.append(fragment_rtt)

        # Calculate average and standard deviation
        if dest_rtts:
            avg_rtt = sum(dest_rtts) / len(dest_rtts)
            std_dev_rtt = (sum((rtt - avg_rtt) ** 2 for rtt in dest_rtts) / len(dest_rtts)) ** 0.5
        else:
            avg_rtt = None
            std_dev_rtt = None

        self.dest_rtt = (avg_rtt, std_dev_rtt)

    def old_get_dest_rtts(self):
        """
        Takes average and stddev of all RTT values for all routes to ultimate destination node. 
        """
        dest_rtts = [connec.rtt for connec in self.endpoint_connecs.values()]

        if dest_rtts:
            avg_rtt = sum(dest_rtts) / len(dest_rtts)
            std_dev_rtt = (sum((rtt - avg_rtt) ** 2 for rtt in dest_rtts) / len(dest_rtts)) ** 0.5
        else:
            avg_rtt = None
            std_dev_rtt = None

        self.dest_rtt = (avg_rtt, std_dev_rtt) 

    def get_avg_rtts(self):
        router_rtts = self.get_intermitt_rtts()
        router_stats = {}

        for router, rtts in router_rtts.items():
            if rtts:
                avg_rtt = sum(rtts) / len(rtts)
                std_dev = math.sqrt(sum((rtt - avg_rtt) ** 2 for rtt in rtts) / len(rtts))
                router_stats[router] = [avg_rtt, std_dev]
            else:
                router_stats[router] = [None, None] 
        return router_stats

    def set_avg_rtts(self):
        self.avg_rtts = self.get_avg_rtts()

    def print_rtt_stats(self):
        for router ,values in self.avg_rtts.items():
            print(f"\n{router:<16}:    {', '.join(map(str, values))}")

    def interm_nodes_str(self):
        self.interm_nodes = self.interm_nodes[1:]
        return "\n".join(node.rjust(75) for node in self.interm_nodes)


