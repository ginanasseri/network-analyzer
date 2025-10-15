import struct

class IP_Header:
    def __init__(self, packet_data, source_IP=None, dest_IP=None, header_len=0, total_len=0):
        self.packet_data = packet_data
        self.source_IP = source_IP
        self.dest_IP = dest_IP
        self.header_len = header_len # Length of IP header (bytes)
        self.total_len = total_len   # Total length of packet (bytes)

    def parse_IP_header(self):
        """
        Updates the source_IP, dest_IP, header_len, and total_len attributes. 
        """
        self.get_source_and_dest_IPs()
        self.get_header_len()
        self.get_total_len()

    def get_source_and_dest_IPs(self):
        """
        Extracts each byte from the source and destination IP addresses into tuples and converts the decimal values
        into strings separated by '.'
        """
        # Unpack source and destination IPs directly into dotted-decimal notation
        self.source_ip = '.'.join(map(str, struct.unpack('BBBB', self.packet_data[12:16])))
        self.dest_ip = '.'.join(map(str, struct.unpack('BBBB', self.packet_data[16:20])))

    def get_header_len(self):
        """
        Extracts the lower nibble from the first byte of the IP header representing 32-bit word
        IP header length and multiplies by 4 to get the header length in bytes. 
        """
        self.header_len = (self.packet_data[0] & 0x0F) * 4

    def get_total_len(self):
        """
        Get total length of packet data in bytes. 
        """
        self.total_len = struct.unpack('>H', self.packet_data[2:4])[0]

class TCP_Header:
    def __init__(self, packet_data, source_port=0, dest_port=0, seq_num=0, ack_num=0, data_offset=0,
                 window_size=0, checksum=0, ugp=0, header_len=0):
        self.packet_data = packet_data
        self.source_port = source_port
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.data_offset = data_offset
        self.window_size = window_size
        self.checksum = checksum
        self.ugp = ugp
        self.header_len = header_len  
        self.flags = self.initialize_flags()

    def initialize_flags(self):
        """Sets default TCP flags."""
        return {"ACK": 0, "RST": 0, "SYN": 0, "FIN": 0}

    def parse_TCP_header(self):
        self.get_source_and_dest_ports()
        self.get_seq_and_ack_nums()
        self.get_flags()
        self.get_header_len()
        self.parse_data_offset()
        self.parse_window_size()
      #  self.relative_seq_num()
      #  self.relative_ack_num()

    def get_source_and_dest_ports(self):
        """
        Extracts the 2 byte source and dest port numbers.
        """
        self.source_port = struct.unpack(">H", self.packet_data[:2])[0]
        self.dest_port = struct.unpack(">H", self.packet_data[2:4])[0]

    def get_seq_and_ack_nums(self):
        """
        Extracts the 4 byte
        """
        self.seq_num = struct.unpack(">I", self.packet_data[4:8])[0]
        self.ack_num = struct.unpack(">I", self.packet_data[8:12])[0]


    def get_flags(self):
        value = struct.unpack("B", self.packet_data[13:14])[0]
        self.flags = {
            "FIN": value & 1,
            "SYN": (value & 2) >> 1,
            "RST": (value & 4) >> 2,
            "ACK": (value & 16) >> 4
        } 

    def get_header_len(self):
        self.header_len = (self.packet_data[12] >> 4) * 4
        

    def parse_data_offset(self):
        self.data_offset = (self.packet_data[12] >> 4) * 4

    def parse_window_size(self):
        self.window_size = struct.unpack(">H", self.packet_data[14:16])[0]


class Packet():
    def __init__(self, packet_No, packet_data, IP_header=None, TCP_header=None, timestamp=None, RTT_value=0, RTT_flag=False, data_length=0):
        self.packet_No = packet_No
        self.packet_data = packet_data
        self.IP_header = IP_header
        self.TCP_header = TCP_header
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = timestamp
        self.data_length = data_length
        self.RTT_value = RTT_value
        self.RTT_flag = RTT_flag

    def init_IP_header(self):
        self.data_empty_test("IP")
        self.IP_header = IP_Header(self.packet_data)

    def init_TCP_header(self):
        self.data_empty_test("TCP")
        self.TCP_header = TCP_Header(self.packet_data)

    def data_empty_test(self, kind):
        if self.packet_data is None:
            raise ValueError(f"Packet data is empty. Cannot parse {kind} header.")

    def parse_IP_and_TCP_headers(self, ip_index=14):
        """
        Initializes the TCP and IP headers with the relevant bytes in the packet data and sets the IP_header 
        source_ip, dest_ip, header len, total_len and the TCP_header source_port, dest_port seq and ack nums, 
        and TCP header length attributes. 
        
        ip_index=14 for ethernet connections
        """
        self.go_to_byte_index(14) # Go to start of IP header
        self.init_IP_header()
        self.IP_header.parse_IP_header()

        self.go_to_byte_index(self.IP_header.header_len) # Go to start of TCP header
        self.init_TCP_header()
        self.TCP_header.parse_TCP_header()

    def timestamp_set(self, ts_sec, ts_usec, orig_time):
        self.timestamp = round(ts_sec + ts_usec / 1e6 - orig_time,6)

    def go_to_byte_index(self, index):
        self.packet_data = self.packet_data[index:]

    def get_RTT_value(self,p):
        rtt = p.timestamp - self.timestamp
        self.RTT_value = round(rtt,8)

    def get_data_length(self):
        tcp_header_len = self.TCP_header.header_len
        ip_header_len = self.IP_header.header_len
        ip_total_len = self.IP_header.total_len
        return ip_total_len - ip_header_len - tcp_header_len


