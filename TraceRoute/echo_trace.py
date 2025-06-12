import struct
import os
import packet_struct as p
import windows as win

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


def run_group_trace(j):
    """
    Run analysis on all trace files in group 1 or 2
    """
    for i in range(1,6):
        fn = f"PcapTracesAssignment3/group{j}-trace{i}.pcap"
        print("=" * 90)
        print(f"{f'Group {j}: Trace {i}':>50}")
        print("=" * 90)
        read_pcap_file(fn)


def run_win_trace():
    for i in range(1,3):
        fn = f"PcapTracesAssignment3/win_trace{i}.pcap"
        print("=" * 90)
        print(f"{f'Win: Trace {i}':>50}")
        print("=" * 90)
        read_pcap_file(fn, windows=True)
        print()

def run_user_file(user_input):
    if '.' in user_input:
        name,ext = user_input.split('.')
    else:
        raise ValueError("Tracefile must have extension type 'pcap'")

    if ext != 'pcap':
        raise ValueError("Tracefile must have extension type 'pcap'")

    else:
        print("=" * 90)
        print(f"{f'{name}':>50}")
        print("=" * 90)
        read_pcap_file(user_input)

def run_frag():
    print("=" * 90)
    print(f"{f'traceroute-frag':>42}")
    print("=" * 90)
    fn = f"PcapTracesAssignment3/traceroute-frag.pcap"
    read_pcap_file(fn)


def run_analysis(user_input):
    ui = user_input.strip()
    if ui == "win":
        run_win_trace()
    elif ui == "group2":
        run_group_trace(2)
    elif ui == "frag":
        run_frag()
    else:
        run_user_file(ui)
    

def read_pcap_file(file_path, stop_value=6, packet_count=0, trace_start_time=None, header=None, windows=False):
 
    win_connections = win.WindowsConnectionData() 

    with open(file_path, 'rb') as f:

        # Parse global header 
        global_header = f.read(24)
        endian = get_endianness(global_header)
        if endian is None:
            raise ValueError("Unknown file format: invalid magic number.")

        # get linktype for link header length 
        linktype = struct.unpack('<I', global_header[20:24])[0] 
        icmp_added=False
        udp_added=False

#        stop = 0

        # --- Start packet parse --- 
        while True:
            packet_header = f.read(16)

            # Break if we've read all packets
            if len(packet_header) < 16:
                break

            # Otherwise, parse packet header
#            packet_count += 1
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', packet_header)

            # Set start time if this is the first packet
            if trace_start_time is None:
                trace_start_time = ts_sec + ts_usec / 1e6

            # Read remaining packet data
            packet_data = f.read(incl_len)

            packet = win.WindowsPacket(packet_count, packet_data, linktype)

#            print(f"Packet Data: {packet.packet_data.hex()}")

            # Parse all IP header data to packet ip_header attribute
            packet.set_IP_header() 

            # parse protocol header following IP header 
            packet.set_protocol_header()

            # If protocol header is None, then packet was not a traceroute packet 
            if packet.protocol_header is None:
                continue
            

            # otherwise, set timestamp and update connections dictionary with current packet 
            packet_count+=1
            packet.set_timestamp(ts_sec, ts_usec, trace_start_time)
#            print(packet)
            win_connections.add_or_update_connections(packet)


    win_connections.get_traceroute_results() # all printing handled in here 


            
def run_trace(user_input):
    run_analysis(user_input)
