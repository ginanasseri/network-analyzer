# TCP Trace

Usage: run `tcptrace.py` and enter packet capture file when prompted. A sample capture file is provided.

## Directory Contents
1. `connections` contains classes and methods to track and update statistics of complete connections. 
2. `minmeanmax` contains MinMeanMax class with methods to calculate and format print the min, mean, max of a data set, and ConnectionsStats class which manages statistics for complete connections.  
3. `packet_struct` general purpose packet struct. Stores the IP and Protocol header, timestamp, and so on. Uses a general `protcocol_header` field, making it a one stop shop for any packet type.
4. `tcptrace` main program that handles control flow of packet capture file parsing. 
