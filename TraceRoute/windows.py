import struct
import math
import packet_headers as h


def print_header():
    print(f"{'Row':<5} {'Components':<60} {'Details'}")
    print("=" * 90)

def print_row(row_num, component, details, divider=True):
    print(f"{row_num:<5} {component:<60} {details}")
    if divider:
        print("-" * 90)

def format_time_value(value):
    if value is not None:
        return f"{value:.5f} ms"


#def format_TTL(ttl, endpoints=False):
#    if not endpoints:
#        return f"TTL {ttl:>2}: {len(v)}"
#    else:
#        return f"TTL {ttl:>2}: {len(self.data.endpoints_data[ttl])}"



class Endpoints:
    def __init__(self, packet):
        self.source_ip = packet.ip_header.source_ip
        self.dest_ip = packet.ip_header.dest_ip

    def __str__(self):
        out = f"Source IP: {self.source_ip} | Dest IP: {self.dest_ip}"


class ICMP_Header:
    def __init__(self, packet_data):
        self.packet_data = packet_data  # Now stores only the relevant data slice
        self.message_type = None
        self.code = None
        self.checksum = None
        self.identifier = None
        self.seq_num = None
        self.orig_ip_header = None
        self.icmp_payload = None

    def get_message_str(self):
        if self.message_type is None:
            return None
        elif self.is_echo_request():
            return "Echo (ping) request"
        elif self.is_ttl_exceeded_type():
            return "Time-to-live exceeded"
        elif self.is_port_unreachable_type():
            return "Port unreachable"

    def is_echo_request(self):
        return self.message_type == 8

    def is_ttl_exceeded_type(self):
        return self.message_type == 11

    def is_port_unreachable_type(self):
        return self.message_type == 3

    def is_echo_reply(self):
        return self.message_type == 0


    def parse_ICMP_header(self):
        self.message_type, self.code = struct.unpack('BB', self.packet_data[:2])
        self.checksum = struct.unpack('!H', self.packet_data[2:4])[0]
        self.identifier = struct.unpack('!H', self.packet_data[4:6])[0]
        self.seq_num = struct.unpack('!H', self.packet_data[6:8])[0]

        # Get original payoad
        if self.is_ttl_exceeded_type():
            orig_ip_data = self.packet_data[8:]  # Start IP header
            self.get_orig_IP_header(orig_ip_data)
            icmp_payload_data = orig_ip_data[self.orig_ip_header.header_len:]  # ICMP payload
            self.get_ICMP_payload(icmp_payload_data)

    def get_orig_IP_header(self, ip_data):
        self.orig_ip_header = h.IP_Header(ip_data)
        self.orig_ip_header.parse_IP_header()

    def get_ICMP_payload(self, icmp_data):
        self.icmp_payload = ICMP_Header(icmp_data)
        self.icmp_payload.parse_ICMP_header()

    def __str__(self):
        out = f"Message Type: {self.message_type:<2} | Code {self.code} | Sequence Number: {self.seq_num}\n"
        return out


class WindowsConnection:
    def __init__(self, echo_packet, response_packet=None):
        self.echo_packet = echo_packet
        self.response_packet = response_packet # ICMP TTL Exceded or Echo reply
        self.rtt = None
    
    def set_response_packet(self, packet):
        self.response_packet = packet
        self.set_rtt()  # calculate RTT when response found

    def set_rtt(self):
        if self.echo_packet and self.response_packet:
            self.rtt = self.response_packet.timestamp - self.echo_packet.timestamp

    def reply_str(self):
        if self.response_packet is not None:
            if self.response_packet.protocol_header.is_ttl_exceeded_type():
                return f"TLL Exceeded"
            elif self.response_packet.protocol_header.is_echo_reply():
                return f"Echo Reply"
#        if self.response_packet.icmp_header.message_type

    def __str__(self):
        output = []
        if self.echo_packet:
            output.append(f"\n\n - - - - - - - - Echo Packet - - - - - - - - - - ")
            output.append(str(self.echo_packet))
        if self.response_packet:
            output.append(f" - - - - - -  {self.reply_str()} Packet - - - - - - - - ")
            output.append(str(self.response_packet))
        if self.rtt is not None:
            output.append(f"   -----------> RTT: {self.rtt:.3f} ms <--------------")
        return "\n".join(output)


class WindowsConnectionData:
    def __init__(self):
        self.data = {}
        self.probes_per = {}
        self.source = None
        self.ultimate_dest = None
        self.avg_rtt = None
        self.std_rtt = None

    def add_or_update_connections(self, packet):
        seq_num = packet.get_seq_num() # returns original datagram seq num if ttl exceeded message
        if seq_num not in self.data:
            self.add_connection(packet, seq_num)
        else:
            self.update_connection(packet, seq_num)

    def add_connection(self, packet, seq_num):
        if packet.protocol_header.is_echo_request():
            if not self.data:
                self.source, self.ultimate_dest = packet.ip_header.source_ip,packet.ip_header.dest_ip
            self.data[seq_num] = WindowsConnection(packet)

    def update_connection(self, packet, seq_num):
        if packet.protocol_header.is_ttl_exceeded_type():
            self.data[seq_num].set_response_packet(packet)
        elif packet.protocol_header.is_echo_reply():  
            if seq_num in self.data:
                self.data[seq_num].set_response_packet(packet)


    def new_add_or_update_connection(self,packet):
        seq_num = packet.get_seq_num()
        if packet.protocol_header.is_echo_request():
            self.add_connection(packet,seq_num)
        elif packet.protocol_header.is_ttl_exceeded_type():
            packet.update_connection(packet, seq_num)        


    def set_rtt_stats(self, endpoints):
        """
        Get avg RTT and stdev for ultimate destiation node
        """
        ultimate_rtts = [connec.rtt for connec in endpoints_data.values()]
        if not ultimate_rtts:
            raise ValueError("Can't determine RTT: No response packet from ultimate destination found.")

        self.avg_rtt = sum(ultimate_rtts)/len(ultimate_rtts)
        self.std_rtt = math.sqrt(sum((rtt - avg_rtt) ** 2 for rtt in ultimate_rtts) / len(ultimate_rtts))


    def get_traceroute_results(self):
        """
        Remove data entries for echo request packets with no corresponding ICMP response.  
        """
        self.data = {
            key: value for key, value in self.data.items() if value.response_packet is not None
        } 

        # ---- Q1, Q2: Get IP address of source and ultimate destination node ----
        endpoints_data = {
            key: value for key, value in self.data.items()
            if value.response_packet.ip_header.source_ip == self.ultimate_dest
        }
        print_header()
        print_row("1","The IP address of the source node (R1)",self.source)
        print_row("2","The IP address of the ultimate destination node (R1)",self.ultimate_dest)


       # ----- Q3, Q4: Get intermediate routers and print in order ----- 
        self.data = {
            key: value for key, value in self.data.items()
            if value.response_packet.ip_header.source_ip != self.ultimate_dest
        }    
        routers_dic, routers_list = self.get_intermit_routers()

        print_row("3","The IP addresses of the intermediate destination nodes (R1)", routers_list[0], divider=False)
        for r in routers_list[1:]:
            print_row("","",r,divider=False)
        print("-" * 90)
    
        # Answer question 4: Routers in order
        print_row("4", "The correct order of the intermediate destination nodes (R1)", routers_list[0], divider=False)
        for r in routers_list[1:]:
            print_row("","",r,divider=False)
        print("-" * 90)


        # --- Q5,6,7 --- 
        # I am assuming this is true for Windows files we'll be using, as we are only matching dealing with 
        # echo requests and ICMP responses in windows traces. 
        print_row("5", "The values in the protocol fields of IP headers (R1))", "1: ICMP")
        print_row("6", "Number of fragments created from the original datagram (R1)", 0)
        print_row("7", "The offset of the last fragment (R1)", 0)

        
        # --- Q8, Q9 
        # get avg RTT and stdev for ultimate destination 
        ultimate_rtts = [connec.rtt for connec in endpoints_data.values()]
        if not ultimate_rtts:
            raise ValueError("Can't determine RTT: No response packet from ultimate destination found.")

        avg_rtt = sum(ultimate_rtts)/len(ultimate_rtts)
        std_dev = math.sqrt(sum((rtt - avg_rtt) ** 2 for rtt in ultimate_rtts) / len(ultimate_rtts))
  
        # Get avg RTT and stdev for all source to routers visited
        self.print_rtt_stats(avg_rtt, std_dev, routers_dic)

        
        # ---- Q10 ---- Part 2 
        # Create mapping of echo request message TTL values to get probes per TTL 
        connecs_per_ttl = {}

        for seq, connec in self.data.items():
            ttl = connec.echo_packet.ip_header.ttl
            if ttl not in self.probes_per:
                connecs_per_ttl[ttl] = [connec]
                self.probes_per[ttl] = [connec.response_packet.ip_header.source_ip]
            else:
                connecs_per_ttl[ttl].append(connec)
                self.probes_per[ttl].append(connec.response_packet.ip_header.source_ip)

        i = True
        for ttl, routers in self.probes_per.items():
            if i:
                print_row("10", "The number of probes per TTL (R2)", f"TTL {ttl:>2}: {len(routers)}",divider=False)
                i = False
            else:
                print_row("","",f"TTL {ttl:>2}: {len(routers)}",divider=False)
#               print_row(f"TTL {ttl}: {len(routers)}")
        print("-" * 90)

    
#        for ttl, connecs in connecs_per_ttl.items():
#            average_rtt = sum(connec.rtt for connec in connecs) / len(connecs#)
   #         print(f"{average_rtt:.1f}")
    
    
            

#            print(f"TTL: {ttl} {[f'{connec.rtt:.4f}' for connec in connecs]}")
##            print(f"TTL: {ttl} {[{connec.rtt}:.4f for connec in connecs]}")
#            for connec in connecs:
#                print(f"RTT: {connec.rtt}")
            

    



    def get_intermit_routers(self):
        """
        Get list of unique routers from all response packets in connections.
        """
        routers = {}
        routers_list = []
               
        for seq, connec in self.data.items():
            if connec.response_packet:  # Ensure the TTL Exceeded packet exists
                router_ip = connec.response_packet.ip_header.source_ip
                if router_ip not in routers:
                    routers[router_ip] = [connec.rtt]
                    routers_list.append(router_ip)
                else:
                    routers[router_ip].append(connec.rtt)

        return routers, routers_list


    def print_rtt_stats(self, ultimate_rtt, ultimate_std, routers):
        """
        Builds a dictionary mapping router IPs to tuples of (average RTT, std deviation).
        """
        stats = {}
        
        for router, rtts in routers.items():
            if rtts:
                avg_rtt = sum(rtts) / len(rtts)
                std_dev = math.sqrt(sum((rtt - avg_rtt) ** 2 for rtt in rtts) / len(rtts))
                stats[router] = (avg_rtt, std_dev)
            else:
                stats[router] = (None, None)

        print_row("8", "The avg RTT to ultimate destination node (R1)",format_time_value(ultimate_rtt) ,divider=False)

        # print intermediate RTTS
        for  router, value in stats.items():
            rtt_avg = format_time_value(value[0])
            print_row("", f"The avg RTT between {self.source} and {router} (R1)", rtt_avg,divider=False)
        print("-" * 90)
                    
        print_row("9", "The stdev of RTT to ultimate destination node (R1)", format_time_value(ultimate_std) ,divider=False)
        # print intermediate RTTS
        for  router, value in stats.items():
            stdev = format_time_value(value[1])
            print_row("", f"The stdev of RTT b/tn {self.source} and {router} (R1)", stdev,divider=False)
        print("-" * 90)


        def __str__(self):
            output = []
            for connec in self.data.values():
                output.append(f"{connec}")
            return "\n".join(output)


class WindowsPacket:
    def __init__(self, packet_num, packet_data, linktype):
        self.packet_num = packet_num
        self.packet_data = packet_data
        self.linktype = linktype
        self.ip_header = None
        self.protocol_header = None # for consistency with Packet Class. This will always be ICMP 
        self.timestamp = None

    def go_to_byte(self, index):
        self.packet_data = self.packet_data[index:]

    def get_IP_header_index(self):
        """
        Returns length of link header depending on linktype: 
              1: Ethernet (14 bytes)    
            113: Linux    (16 bytes)
            276: Linux v2 (20 bytes)
        """
        if self.linktype == 1:
            return 14
        elif self.linktype == 113:
            return 16
        elif self.linktype == 276:
            return 20
        else:
            return None

    def set_IP_header(self):
        ip_index = self.get_IP_header_index()
        if ip_index is None:
            raise ValueError(f"Unknown linktype: {linktype}.")
        self.go_to_byte(ip_index)
        self.ip_header = h.IP_Header(self.packet_data)
        self.ip_header.parse_IP_header()
        self.go_to_byte(self.ip_header.header_len) # go to end of IP header 

    def set_protocol_header(self):
        """
        Set protocol_header to None if not a relevant traceroute packet. 
        """
        if self.ip_header.protocol == 1:
            self.protocol_header = ICMP_Header(self.packet_data)
            self.protocol_header.parse_ICMP_header()
        else:
            self.protocol_header = None

    def set_timestamp(self, ts_sec, ts_usec, orig_time):
        self.timestamp = round(ts_sec + ts_usec / 1e6 - orig_time,6)

    def get_seq_num(self):
        if self.protocol_header.is_echo_request():
            return self.protocol_header.seq_num
        elif self.protocol_header.is_ttl_exceeded_type():
            return self.protocol_header.icmp_payload.seq_num
        elif self.protocol_header.is_echo_reply():
            return self.protocol_header.seq_num
    


    def __str__(self):
        out = "------------------------------------------------\n"
        out+= self.ip_header.get_summary_str()
        out+= "------------------------------------------------\n"
        out+= f" ICMP: {self.protocol_header.get_message_str()}  (packet {self.packet_num})\n"
        out+= "------------------------------------------------\n"
        out+= str(self.protocol_header)
        if self.protocol_header.is_ttl_exceeded_type():
            out+= "------------------------------------------------\n"
            out+= " + + + + + + Original Payload + + + + + + + + + \n"
            out+= "------------------------------------------------\n"
            out+= "------------------------------------------------\n"
            out+= self.protocol_header.orig_ip_header.get_summary_str()
            out+= "------------------------------------------------\n"
            out+= f" ICMP: {self.protocol_header.icmp_payload.get_message_str()}\n"
            out+= "------------------------------------------------\n"
            out+= str(self.protocol_header.icmp_payload)
        out+= "================================================"
        return out

