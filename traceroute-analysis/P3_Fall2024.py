import struct
import os
import packet_struct as p
import linux_trace as linux_trace
import echo_trace as echo_trace
import welcome_message as wm

def get_endianness(global_header):
    """
    Reads magic number in global header and returns the endianness of the file.
    """
    magic_number = struct.unpack('>I', global_header[0:4])[0]
    if magic_number in {0xA1B2C3D4, 0xA1B23C4D}:
        return '>'  # Big-endian
    elif magic_number in {0xD4C3B2A1, 0x4D3CB2A1}:
        return '<'  # Little-endian
    else:
        return None


def run_group_trace(j, user_input):
    """
    If this is for group1 or group2, open the first file to get the file type for trace.
    """
    fn = f"PcapTracesAssignment3/group{j}-trace1.pcap"
    read_pcap_file(fn, user_input)

def run_win_trace(user_input):
    fn = f"PcapTracesAssignment3/win_trace1.pcap"
    read_pcap_file(fn, user_input)


def run_user_file(user_input):
    if not os.path.exists(user_input):
        raise ValueError(f"Could not find file: {user_input}")
    if '.' in user_input:
        name,ext = user_input.split('.')
    else:
        raise ValueError("Tracefile must have extension type 'pcap'")
    if ext != 'pcap':
        raise ValueError("Tracefile must have extension type 'pcap'")
    else:
        file_path = user_input
        read_pcap_file(file_path, user_input)

def run_frag(user_input):
    fn = f"PcapTracesAssignment3/traceroute-frag.pcap"
    read_pcap_file(fn, user_input)


def run_analysis(user_input):
    ui = user_input.strip()
    if ui == "group1":
        run_group_trace(1,user_input)
    elif ui == "group2":
        run_group_trace(2, user_input)
    elif ui == "win":
        run_win_trace(user_input)
    elif ui == "frag":
        run_frag(user_input)
    else:
        run_user_file(ui)
    

def read_pcap_file(file_path, user_input, stop_value=6, packet_count=0, trace_start_time=None, header=None):
 

    with open(file_path, 'rb') as f:

        # Parse global header 
        global_header = f.read(24)
        endian = get_endianness(global_header)
        if endian is None:
            raise ValueError("Unknown file format: invalid magic number.")

        # get linktype for link header length 
        linktype = struct.unpack('<I', global_header[20:24])[0] 

        # --- Start packet parse --- 
        while True:
            packet_header = f.read(16)

            # Break if we've read all packets
            if len(packet_header) < 16:
                break

            # Otherwise, parse packet header
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', packet_header)


            # Set start time if this is the first packet
            if trace_start_time is None:
                trace_start_time = ts_sec + ts_usec / 1e6 


            # Read remaining packet data
            packet_data = f.read(incl_len)
            packet = p.Packet(packet_count, packet_data, linktype)
            packet.set_timestamp(ts_sec, ts_usec, trace_start_time)

            # Parse all IP header data to packet ip_header attribute
            packet.set_IP_header() 
            packet_count +=1 # for checking with wireshark 

            # parse protocol header following IP header 
            packet.set_protocol_header()

            # If protocol header is None, then packet was not a traceroute packet 
            if packet.protocol_header is None:
                continue
            
            if packet.is_udp():
                f.close()
                linux_trace.run_trace(user_input)                           
                break
 
            elif packet.is_icmp() and packet.protocol_header.is_echo_request():
                f.close()
                echo_trace.run_trace(user_input)
                break
                
     
            
def main():
    # Ask the user for a filename
    wm.print_welcome_message()
    user_input = input("> Enter shortcut or filename: ")
    run_analysis(user_input)



if __name__ == "__main__":
    main()

