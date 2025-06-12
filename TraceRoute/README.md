# TraceRoute

To run the program use `python P3_Fall2024.py`. The following output will be printed:


```
    P3_Fall2024: IP Analysis Tool.

  
    Usage: Enter '.pcap' file or one of the following shortcuts to run analysis on file/filegroup specified.
  

    'group1'  group 1 traces (5 total)

    'group2'  group 2 traces (5 total)

    'win' windows traces     (2 total)

    'frag'  traceroute-frag.pcap
  

    > Enter shortcut or filename:

```

 The commands listed above are shortcuts for ease of use. For example, if you enter 'group1' (without the quotations), the analysis 
 will run on all group1 trace files, similarly with 'group2'. You may also enter a file of your choosing. 

### Directory Contents:
1. `R2_answers.pdf` - written answers to part 2 are here. 

2. `P3_Fall2024.py` - the main program for P3. Diverts to `linux_trace` or `echo_trace` to handle UDP/ICMP traces or ICMP only
                      traces (ping ) depending on the file content. 

Program Contents:

    - `linux_trace`   - acts as main for Linux type traces (UDP/ICMP source port pairings)

    - `packet_struct` - General purpose packet struct. Stores the IP and Protocol header, timestamp, and so on. 
                      - Uses a general `protcocol_header` field, making it a one stop shop for any packet type.

    - `packet_header` - Contains IP Header, UDP Header, and ICMP Header classes for accessing and storing data parsed from header.

    - `connections`   - Contains a connection class a request and corresponding response packet. 
                      - For Linux traces: UDP probe and ICMP timeout request
                      - Winodws: Echo requet and ICMP time out request and Echo request and echo reply.
                      - Contains classes and  methods for finding matches, calclating RTT values, handling fragments, and so on

    - `echo_trace`    - acts as main for ICMP Echo Requst and ICMP Response sequence pairing (Windows and ping trace files).

    - `windows`       - contains additional classes and methods for handling echo/icmp ttl exceeded traceroutes packets. Contains its own 
                        packet type and ICMP header clas -- this is for all echo request/icmp TTL exceeded traces, not restricted to windows.
    
    - `print_traceroute`  -  Contains a class to help manage all data for format printing.

    - `welcome_message` - prints the welcome message 


### Comments : 


- There are a few extreme RTT and STDEV values in my output due my parsing of `ts_usec` in the global header. It only goes arway for a few data points. I touch on this briefly in `R2_answers.pdf`.

