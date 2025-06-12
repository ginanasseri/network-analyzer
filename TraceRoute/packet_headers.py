import struct

class IP_Header:
    def __init__(self, packet_data, source_ip=None, dest_ip=None, header_len=None, total_len=None, id_num=None, ttl=None, protocol=None, frag_offset=None, header_checksum=None):
        self.packet_data = packet_data
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.header_len = header_len # Length of IP header (bytes)
        self.total_len = total_len   # Total length of packet (bytes)
        self.id_num = id_num
        self.frag_offset = frag_offset
        self.ttl = ttl
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.flags = self.initialize_flags()

    def initialize_flags(self):
        return {"RS": 0, "DF": 0, "MF": 0}

    def parse_IP_header(self):
        self.get_header_len()
        self.get_total_len()
        self.get_id_num()
        self.get_fragment_settings() # get flags and fragment offset
        self.get_ttl_and_protocol()
        self.get_source_and_dest_IPs()

    def get_header_len(self):
        """
        Get IP header length: extract bits [4:8] of byte 0 in IP header and multiply by 4 to get the 32-bit 
        word value. Minimum value = 20.
        """
        self.header_len = (self.packet_data[0] & 0x0F) * 4

    def get_total_len(self):
        self.total_len = struct.unpack('!H', self.packet_data[2:4])[0]

    def get_id_num(self):
        self.id_num = struct.unpack('!H', self.packet_data[4:6])[0]
        
    def get_fragment_settings(self):
        flags_and_offset = struct.unpack('!H', self.packet_data[6:8])[0]
#        print(f"Raw flags and offset: {flags_and_offset:016b}     ({flags_and_offset:#06x})")
        flag_values = (flags_and_offset & 0xE000) >> 13
#        print(f"Raw flags: {flag_values:03b}")
        self.frag_offset = flags_and_offset & 0x1FFF
#        print(f"Raw offset: {self.frag_offset:013b}")
        self.get_flags(flag_values)
        return self.frag_offset
    
    def get_flags(self, flag_values):
        self.flags = {
            "RS": (flag_values & 4) >> 2,
            "DF": (flag_values & 2) >> 1,
            "MF": (flag_values & 1),       
        }

    def get_ttl_and_protocol(self):
        self.ttl, self.protocol = struct.unpack('BB', self.packet_data[8:10])
        
    def get_source_and_dest_IPs(self):
        """
        Extracts each byte from the source and destination IP addresses and formats the decimal values as strings separated by '.'
        """
        # Unpack source and destination IPs directly into dotted-decimal notation
        self.source_ip = '.'.join(map(str, struct.unpack('BBBB', self.packet_data[12:16])))
        self.dest_ip = '.'.join(map(str, struct.unpack('BBBB', self.packet_data[16:20])))

    def get_summary_str(self):
#        out = f"------------------------------------------------\n"
        out = f"Source IP: {self.source_ip:<14} | Dest IP: {self.dest_ip}\n"
        out+= f"Protocol : {self.protocol:<14} | TTL    : {self.ttl}\n"
      #  out+= f"------------------------------------------------\n"
        return out

    def __str__(self):
        flags_str = f"RS: {self.flags['RS']} | DF: {self.flags['DF']} | MF: {self.flags['MF']}"
        return (f"Source IP  : {self.source_ip}\n"
                f"Dest. IP   : {self.dest_ip}\n"
           #     f"Header Length: {self.header_len} bytes\n"
           #     f"Total Length: {self.total_len} bytes\n"
                f"ID         : 0x{self.id_num:04x}\n"
                f"TTL        : {self.ttl}\n"
          #      f"Protocol: {self.protocol}\n"
                f"Frag Offset: {self.frag_offset}\n"
                f"Flags      : {flags_str}")
    

class UDP_Header:
    def __init__(self, packet_data, ip_header, source_port=None, dest_port=None, length=0, checksum=None, data=None):
        self.packet_data = packet_data
        self.ip_header = ip_header
        self.source_port = source_port
        self.dest_port = dest_port
        self.length = length
        self.checksum = checksum
        self.data = data

    def parse_UDP_header(self,icmp=False):
        self.get_ports()
        self.get_length()
        self.get_checksum()
        if not icmp:
            self.get_data() # only get 1st 8 bytes if ICMP message 

#    def timestamp_set(self, ts_sec, ts_usec, orig_time):
#        self.timestamp = round(ts_sec + ts_usec / 1e6 - orig_time,6)

    def get_ports(self):
        self.source_port = struct.unpack('!H', self.packet_data[:2])[0]
        self.dest_port = struct.unpack('!H', self.packet_data[2:4])[0]

    def get_length(self):
        self.length = struct.unpack('!H', self.packet_data[4:6])[0]

    def get_checksum(self):
        self.checksum = struct.unpack('!H', self.packet_data[6:8])[0]

    def get_data(self):
        data_length = self.length - 8 # subtract 8 byte UDP header to get data length
        self.data = self.packet_data[8:8 + data_length] 

    def in_range(self, port):
        if port >= 33434 and port <= 33529:
            return True
        return False

    def is_udp_fragment(self):
        return self.ip_header.flags["MF"] == 1 or self.ip_header.frag_offset > 0

    def is_traceroute_packet(self):
        if self.is_udp_fragment():
            return True
        return self.in_range(self.dest_port)

    def __str__(self):
        return (f"{self.ip_header}\n"
                f"Source port: {self.source_port}\n"
                f"Destination port: {self.dest_port}\n")
#                f"Length: {self.length} bytes")

class ICMP_Header:
    def __init__(self, packet_data, ip_header, orig_ip_header=None, udp_payload=None, message_type=None, code=None, checksum=None, unused=None): 
        self.packet_data = packet_data
        self.ip_header = ip_header
        self.message_type = message_type
        self.code = code 
        self.checksum = checksum
        self.unused = unused
        self.orig_ip_header = orig_ip_header
        self.udp_payload = udp_payload

#    def timestamp_set(self, ts_sec, ts_usec, orig_time):
#        self.timestamp = round(ts_sec + ts_usec / 1e6 - orig_time,6)

    def is_echo_request(self):
        return self.message_type == 8

    def is_ttl_exceeded_type(self):
        return self.message_type == 11

    def is_port_unreachable_type(self):
        return self.message_type == 3
 
    def parse_ICMP_header(self):
        self.message_type, self.code = struct.unpack('BB', self.packet_data[:2])
        self.checksum = struct.unpack('!H', self.packet_data[2:4])[0]
        self.unused = struct.unpack('BBBB', self.packet_data[4:8])[0]
        self.get_orig_IP_header()
        self.get_UDP_payload()

    def get_source_ip(self):
        return self.ip_header.source_ip

    def get_orig_IP_header(self):
        self.packet_data = self.packet_data[8:]
        self.orig_ip_header = IP_Header(self.packet_data)
        self.orig_ip_header.parse_IP_header()

    def get_UDP_payload(self):
        self.packet_data = self.packet_data[self.orig_ip_header.header_len:]
        self.udp_payload = UDP_Header(self.packet_data, self.orig_ip_header)
        self.udp_payload.parse_UDP_header()

    def __str__(self):
        return (f"{self.ip_header}\n"
                f"Message type: {self.message_type}\n"
                f"Code: {self.code}\n"
                f"--- Original IP --- \n"
                f"{self.orig_ip_header}\n"
                f"{self.udp_payload}")


