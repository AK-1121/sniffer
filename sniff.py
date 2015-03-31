# ONLY FOR LINUX !!!

# Use script only in sudo mode!!!

# You can write output of the sniff-script to file with this command:
# python sniff.py > output.txt

import socket
import struct
import datetime

# create socket:
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)



while True:
    packet = sock.recvfrom(65535)
    print("\n"+"="*30)
    # print("packet:", type(packet))
    
    packet = packet[0]

    # get first 20 characters for the ip header:
    # about IP-header: http://en.wikipedia.org/wiki/IPv4#Header
    ip_header = packet[0:20]
    # https://docs.python.org/2/library/struct.html
    # B	- unsigned char -	integer	- 1 byte
    # H - unsigned short -	integer	- 2 bytes

    # in our case:
    # 0: B - IP protocol version(4bit) + Internet Header Length (IHL) (4bit)
    # 1: B - DSCP +	ECN (1byte)
    # 2: H - Total Length of packet (header+data) (16bit). Max = 65,535 bytes.
    # 3: H - Identifier of packet for uniquely identifying the group 
    #        of fragments of a single IP datagram (16bit).
    # 4: H - Flags + Fragment Offset (16bit)
    # 5: B - TTL
    # 6: B - Protocol: 0x06 - TCP, 0x11 - UDP, 0x1B - RDP, ...
    # 7: H - Header Checksum

    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    # Internet Header Length(IHL) is the number of 32-bit words in the header:
    ihl = version_ihl & 0xF



    iph_len = ihl * 4  # Convert dimention of len from 32bit words to bytes
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]) # Convert: \xc0\xa8\x00e -> 192.168.0.101
    d_addr = socket.inet_ntoa(iph[9])
    
    print(datetime.datetime.now().strftime("%d-%m %H::%m::%S"))
    print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) +
          ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) +
          ' Source Address : ' + str(s_addr) + ' Destination Address : ' +
          str(d_addr))

    tcp_header = packet[iph_len:iph_len+20]
    tcph_unpacked = struct.unpack('!HHLLBBHHH', tcp_header)  # Unpack packet.
    # http://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    # 0: H - Source port
    # 1: H - Destination port
    # 2: L - Sequence number (4 bytes)
    # 3: L - Acknowledgment number
    # 2-3 - numbers for organizing tcp control of packets delivery
    # 4: B - Data offset (4 bits) + Reserv (3bits) + flag(1bit)
    # Data offset - size of TCP header in 32-bit words
    print("Source port: " + str(tcph_unpacked[0]) +
          "; Destination port: " + str(tcph_unpacked[1]))

    tcph_len = tcph_unpacked[4] >> 4
    tcp_ip_header_size = iph_len + tcph_len

    data = packet[tcp_ip_header_size:]  # extract data from files
    print("Data :" + str(data))

