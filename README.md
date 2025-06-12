# Network Tools

This repo contains two packet analysis programs that parse packet capture files to extract network statistics and display them in human-readable form:

## TCPTrace 

Processes TCP trace files by parsing TCP protocol headers to track connection states, calculate round-trip times, and count packets and data/sent received in completed connections.

## TraceRoute

Processes IP trace files by parsing IP datagrams to pair sent TTL probes with corresponding ICMP time-exceeded messages to extract the IP route, round-trip times per TTL probe, and fragment statistics of the original datagram. 

Note: each directory contains a README explaining directory contents and usage of each program. 
