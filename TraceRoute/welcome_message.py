def print_welcome_message():
    message = f"\n P3_Fall2024: IP Analysis Tool.\n"
    message+= f"\n Usage: Enter '.pcap' file or one of the following shortcuts to run analysis on file/filegroup specified.\n\n"
#    message+= f"The follow.\n\n"
#    message+= f" The following values can be used as shortcuts to analyse the file/filegroup specified.\n\n"
#    message+= f" The following input can be used as shortcut to run analysis on the file/filegroup specified:\n\n"

    message+= f"\t'group1'          group 1 traces (5 total)\n"
    message+= f"\t'group2'          group 2 traces (5 total)\n"
    message+= f"\t'win'             windows traces (2 total)\n"
    message+= f"\t'frag'            traceroute-frag.pcap\n\n"

    print(message)
