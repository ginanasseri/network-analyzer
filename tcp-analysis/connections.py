import packet_struct
import minmeanmax as mmm

# Global tracker to get all values for part D 
complete_data = mmm.CompleteConnectionStats() # duration_data, RTT_data, packet_number_data, window_size_data

class Endpoints:
    def __init__(self, packet):
        self.source = (packet.IP_header.source_ip, packet.TCP_header.source_port)
        self.dest = (packet.IP_header.dest_ip, packet.TCP_header.dest_port)

    def get_four_tuple_key(self):
        return tuple(sorted([self.source, self.dest]))

    def __str__(self):
        return f"Source Address: {self.source[0]}\nDestination Address: {self.dest[0]}\nSource Port: {self.source[1]}\nDestination Port: {self.dest[1]}"

class PacketTracker:
    """
    Used for tracking number of packets and bytes sent and recevied over a single connection. 
    """
    def __init__(self, current_packet=None, packets_sent=0, packets_received=0, bytes_sent=0, bytes_received=0, total_packets=0, total_bytes=0):
        self.current_packet = current_packet
        self.packets_sent = packets_sent         # packets from source to destination
        self.packets_received = packets_received # packets from destination to source
        self.bytes_sent = bytes_sent             # bytes from source to destination
        self.bytes_received = bytes_received     # bytes from destination to source
        self.total_packets = total_packets
        self.total_bytes = total_bytes

    def update_packet_stats(self, packet, outgoing):
        """
        Track packet number and data length from source to destination (outgoing = True) and destination to source (outgoing = False) and track window sizes 
        for each packet
        """
        self.current_packet = packet
        if outgoing:
            self.update_packets_sent()
        else:
            self.update_packets_received()

        self.total_packets = self.packets_sent + self.packets_received
        self.total_bytes = self.bytes_sent + self.bytes_received

    def update_packets_sent(self):
        """
        Update the number of packets and number of data bytes sent from source to destination.
        """
        self.packets_sent += 1
        data_length = self.current_packet.get_data_length()
        self.bytes_sent += self.current_packet.get_data_length()

    def update_packets_received(self):
        """
        Update the number of packets and number of data bytes sent from destination to source.
        """
        self.packets_received += 1
        data_length = self.current_packet.get_data_length()
        self.bytes_received += self.current_packet.get_data_length()

class Connection:
    def __init__(self, connection_no, current_packet, endpoints, start_time, end_time=None, outgoing=True, packet_tracker=None, RTT=None):
        self.connection_no = connection_no
        self.current_packet = current_packet
        self.endpoints = endpoints            # [(source_IP, source_port), (dest_IP, dest_port)]
        self.packet_tracker = packet_tracker
        self.start_time = start_time
        self.end_time = end_time
        self.packets = []
        self.outgoing = outgoing
        self.state = [0,0,0] # state[0] = num SYN, state[1] = num FIN, state[2] = 1 if RST  

    def packet_direction_outgoing(self, outgoing=True):
        """
        Returns the direction of the current packet between the source and destination endpoints. If the source IP of the current
        packet is the same as the source IP of the established connection, then outgoing is True. Otherwise, the packet direction
        is from destination to source, and outgoing is False.
        """
        if self.current_packet.IP_header.source_ip != self.endpoints.source[0]:
            outgoing=False
        return outgoing

    def update_state(self):
        """
        Tracks the number of SYN and FIN messages sent in state[0] and state[1], respectively, and sets state[2]=1 if RST flag is set.
        """
        if self.current_packet.TCP_header.flags["SYN"] == 1:
            self.state[0] += 1

        if self.current_packet.TCP_header.flags["FIN"] == 1:
            self.state[1] += 1

        if self.current_packet.TCP_header.flags["RST"] == 1:
            self.state[2] = 1

    def start_packet_tracker(self):
        self.packet_tracker = PacketTracker(self.current_packet)

    def update_end_time(self):
        if self.current_packet.TCP_header.flags["FIN"] == 1:
            self.end_time = self.current_packet.timestamp

    def update_connection(self, packet, outgoing=True):
        self.current_packet = packet
        self.packets.append(self.current_packet)
        self.update_state()
        self.update_end_time()
        self.outgoing = self.packet_direction_outgoing()
        self.packet_tracker.update_packet_stats(self.current_packet, self.outgoing)

    def get_state_str(self):
        """
        Format state for printing
        """
        state_str = f"S{self.state[0]}F{self.state[1]}"
        if self.state[2] == 1:
            state_str += "/R"
        return state_str

    def __str__(self):
        state_str = self.get_state_str()
        connection_str = f"Connection {self.connection_no}:\n{self.endpoints}\nStatus: {state_str}"
        no_packets = f"Number of packets sent from" 
        no_bytes = f"Number of data bytes sent from"

        # Print remaining stats if connection is complete (has at least one SYN and one FIN)
        if self.state[0] >= 1 and self.state[1] >= 1:
            connection_str += f"\nStart time: {self.start_time:.6f} seconds\nEnd Time: {self.end_time:.6f} seconds\nDuration: {self.end_time - self.start_time:.6f} seconds\n"
            connection_str += f"{no_packets} Source to Destination: {self.packet_tracker.packets_sent}\n"
            connection_str += f"{no_packets} Destination to Source: {self.packet_tracker.packets_received}\nTotal number of packets: {self.packet_tracker.total_packets}\n"
            connection_str += f"{no_bytes} Source to Destination: {self.packet_tracker.bytes_sent}\n"
            connection_str += f"{no_bytes}Destination to Source: {self.packet_tracker.bytes_received}\nTotal number of data bytes: {self.packet_tracker.total_bytes}\nEND"
        connection_str += f"\n++++++++++++++++++++++++++++++++"
        return connection_str


class ConnectionData:
    """
    Dictionary of Connections where the each key is the 4-tuple of a unique connection 
    """
    def __init__(self, complete=0, reset=0, total=0, closed=0, prev_established=0):
        self.connections = {}
        self.complete = complete
        self.reset = reset
        self.complete = complete
        self.closed = closed # closed but not complete S0F2  
        self.prev_established = prev_established
        self.total = total

    def get_num_open(self):
        """
        Number of connections open 
        """
        return self.total - self.closed - self.complete

    def add_or_get_connection(self, packet, endpoints): #source_ip, source_port, dest_ip, dest_port):
        """
        Returns the connection corresponding to the four-tuple (source_IP, source_port, dest_IP, dest_port) in the connections 
        dictionary. If no entry exists, then a new entry is created where the key is the connection's four tuple and the data 
        is a new connection, updated with the current packet data. The dictionary keys are a set. 

        Args:
            Packet p - the current packet being parsed. 
        """

        # Get connection four-tuple (set) 
        four_tuple = endpoints.get_four_tuple_key()

        # If the connection doesn't exist in any direction, create a new one. 
        if four_tuple not in self.connections:
            connection = Connection(connection_no=len(self.connections) + 1, current_packet=packet, endpoints=endpoints, start_time=packet.timestamp)
            connection.start_packet_tracker() # initialize packet tracker 
            self.connections[four_tuple] = connection

        # Return the existing or new connection
        return self.connections[four_tuple]


    def get_win_size_and_RTT(self, connec):
        for i,p in enumerate(connec.packets):

            # Get window sizes
            complete_data.update_list("window_size", p.TCP_header.window_size)

            # Get RTT values  
            data_len = p.get_data_length()

            # If the packet is outgoing with non-zero payload
            if p.IP_header.source_ip == connec.endpoints.source[0] and p.TCP_header.flags["RST"] != 1 and data_len != 0:

                # Destination's sent ACK number will be source's sequence number + data length 
                expected_ack = p.TCP_header.seq_num + data_len
                for next_p in connec.packets[i+1:]:
                    if next_p.TCP_header.ack_num == expected_ack:
                        timestamp_a = p.timestamp
                        timestamp_b = next_p.timestamp
                        rtt = timestamp_b - timestamp_a 
                        complete_data.update_list("RTT", rtt)
                        break  # Stop once the first matching ACK is found



    def get_connection_stats(self):
        """
        Analyzes each connection in the tracefile. 
        """
        self.total = len(self.connections)

        for connec in self.connections.values():
        
            # Reset 
            if connec.state[2] == 1:
                self.reset += 1

            # Previously established cases-- No SYN on capture
            if connec.state[0] == 0:
                self.prev_established += 1

                # Previously connected and closed: S0F2, S0F1 (SXF1=complete for X=1,2, therefore assumed S0F1 can be considered closed.)
                if connec.state[1] >= 1:
                    self.closed += 1  

            # Complete connection stats
            if connec.state[0] >= 1 and connec.state[1] >= 1:

                self.complete+=1
                complete_data.update_list("duration", connec.end_time - connec.start_time)
                complete_data.update_list("packet_number", connec.packet_tracker.total_packets)

                self.get_win_size_and_RTT(connec)


    def get_general_TCP_data(self):
        num_open = self.get_num_open()
        general = f"Total number of complete TCP connections: {self.complete}\n"
        general += f"Number of reset TCP connections: {self.reset}\nNumber of TCP connections that were still open when the trace capture ended: {num_open} \n"
        general += f"Number of TCP connections established before the capture started: {self.prev_established}"
        return general

    
    def get_complete_stats(self):
        complete_data.get_results()

    def __str__(self, num=0, max_num=1):
        connection_str = "" # build formatted string for all connections 
        for connec in self.connections.values():
            connection_str += str(connec) + "\n"

        part_C_str = self.get_general_TCP_data()
        

        return f"\nA) Total number of connections: {len(self.connections)}\
                \n________________________________________________\
                \n\nB) Connections' details:\n\n{connection_str}\
                \n________________________________________________\
                \n\nC) General\n\n{part_C_str}\
                \n________________________________________________\n\nD) Statistics\n"

