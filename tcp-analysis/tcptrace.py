import struct
import os
import packet_struct as p 
import connections as c

def get_endianness(global_header):
    """
    Reads magic number in global header and returns the endianness of the file. 
    """
    magic_number = struct.unpack('>I', global_header[0:4])[0]
    if magic_number == 0xA1B2C3D4:
        return '>'  # Big-endian
    elif magic_number == 0xD4C3B2A1:
        return '<'  # Little-endian
    else:
        return None

def read_pcap_file(file_path):

    with open(file_path, 'rb') as f:

        # Parse global header 
        global_header = f.read(24)
        endian = get_endianness(global_header)
        if endian is None:
            raise ValueError("Unknown file format: invalid magic number.")

        packet_count = 0 
        trace_start_time = None
        connections = c.ConnectionData() # dictionary to manage connections

        # Start packet parse
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

            # Create new packet instance  
            packet = p.Packet(packet_count, packet_data) 
            packet.timestamp_set(ts_sec, ts_usec, trace_start_time)

            # Get source and dest IPs, ports, packet length, and packet header lengths
            packet.parse_IP_and_TCP_headers()
            packet.get_data_length()

            # Get four-tuple identifier key for current packet  
            endpoints = c.Endpoints(packet)

            # Lookup/create connection in connection dictionary using four-tuple key
            current_connection = connections.add_or_get_connection(packet, endpoints)

            # Update connection with packet data.  
            current_connection.update_connection(packet)
   
    # Get stats on all connections in connections dictionary. 
    connections.get_connection_stats() 
    print(connections)

    # Get stats on complete connections 
    connections.get_complete_stats()

def main():
    filename = input("Enter tracecap file for analysis: ")

    # Check if the file exists
    if not os.path.isfile(filename):
        print("Error: Could not find file.")
        return

    read_pcap_file(filename)


if __name__ == "__main__":
    main()

