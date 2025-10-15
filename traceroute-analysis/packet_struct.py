import struct
import packet_headers as h 

class Packet():
    def __init__(self, packet_num, packet_data, linktype, ip_header=None, protocol_header=None, timestamp=None, protocol_type=None):
        self.packet_num = packet_num
        self.packet_data = packet_data
        self.linktype = linktype
        self.ip_header = ip_header
        self.protocol_header = protocol_header
        self.timestamp = timestamp
        self.protocol_type = protocol_type

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

    def is_icmp(self):
        return self.ip_header.protocol == 1

    def is_udp(self):
        return self.ip_header.protocol == 17

    def get_source_port(self):
        if self.is_icmp():
            return self.protocol_header.udp_payload.source_port
        if self.is_udp():
            return self.protocol_header.source_port

    def get_ip_id(self):
        if self.is_icmp():
            return self.protocol_header.orig_ip_header.id_num
        if self.is_udp():
            return self.protocol_header.ip_header.id_num 

    def get_MF_value(self):
        if self.is_icmp():
            return self.protocol_header.orig_ip_header.flags["MF"]
        if self.is_udp():
            return self.protocol_header.ip_header.flags["MF"]

    def get_frag_offset(self):
        if self.is_icmp():
            return self.protocol_header.orig_ip_header.frag_offset
        if self.is_udp():
            return self.protocol_header.ip_header.frag_offset
    

    def set_protocol_header(self):
        """
        Set protocol_header to None if not a relevant traceroute packet. 
        """
        if self.ip_header.protocol == 1:
            self.protocol_header = h.ICMP_Header(self.packet_data, self.ip_header)
            self.protocol_header.parse_ICMP_header()
#            print(f"ICMP OG SOURCE PORT NUM: {self.protocol_header.udp_payload.source_port}")

        elif self.ip_header.protocol == 17:
            self.protocol_header = h.UDP_Header(self.packet_data, self.ip_header)
            self.protocol_header.parse_UDP_header()
#            print(f"UDP SOURCE PORT NUM: {self.protocol_header.source_port}")
#            print(f"UDP DEST PORT NUMBER: {self.protocol_header.dest_port}")
            if not self.protocol_header.is_traceroute_packet():
                self.protocol_header = None # DNS packet 
        else:
            self.protocol_header = None
        

    def set_timestamp(self, ts_sec, ts_usec, orig_time=0):
        self.timestamp = round(ts_sec + ts_usec / 1e6 - orig_time,6)

    def print_packet(self):
        out=f"UDP packet"
        out+=f"---------------------------------\n"
        out+=f"Source Port: {self.protocol_header.source_port}"
        out+=f"Dest. IP: {self.protocol_header.ip_header.dest_ip} | "
        out+=f"Timestamp: {self.timestamp}"


    def __str__(self, out=None):
        if self.is_icmp():
            out = f"-- ICMP -----"   #: Source Port: {self.protocol_header.udp_payload.source_port} | 
            out+=f"---------------------\n"
            out+=f"Source Port: {self.protocol_header.udp_payload.source_port}\n"
            out+=f"{self.protocol_header.ip_header}\n"
            out+=f"Timestamp  : {self.timestamp}"
        elif self.is_udp():
            out=f"-- UDP ------"
            out+=f"---------------------\n"
            out+=f"Source Port: {self.protocol_header.source_port}\n"
            out+=f"{self.protocol_header.ip_header}\n"
            out+=f"Timestamp  : {self.timestamp}\n"
            out+= f"---------------------------------"


        return out

