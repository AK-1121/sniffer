# ONLY FOR LINUX !!!
# use sudo

import socket
import struct
import datetime

# create socket:
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

while True:
    packet = sock.recvfrom(40960)
    print("packet:", type(packet))
    
    packet = packet[0]
    print("packet:", type(packet) ,len(packet))
    print("packet[10]:", packet[:30])


    # get first 20 characters for the ip header:
    # about IP-header: http://en.wikipedia.org/wiki/IPv4#Header
    ip_header = packet[0:20]
    # https://docs.python.org/2/library/struct.html
    # B	- unsigned char -	integer	- 1 byte
    # H - unsigned short -	integer	- 2 bytes

    # in our case:
    # 1: B - version(4bit) + IHL(4bit)
    # 2: B - DSCP +	ECN (1byte)
    # 3: H - Total Length of packet (16bit)
    # 4: H - Identifier of packet for uniquely identifying the group 
    #        of fragments of a single IP datagram (16bit).
    # 5: H - Flags + Fragment Offset (16bit)
    # ...
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    # Internet Header Length(IHL) is the number of 32-bit words in the header:
    ihl = version_ihl & 0xF
    print("version_ihl:", version_ihl, "bin:", bin(version_ihl))
    print("version:", version, "ihl:", ihl)



    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    
    print(datetime.datetime.now().strftime("%d-%m %H::%m::%S"))
    print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) +
          ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) +
          ' Source Address : ' + str(s_addr) + ' Destination Address : ' +
          str(d_addr))

    

    """
    print('Source Port : ' + str(source_port) + ' Dest Port : ' +
          str(dest_port) + ' Sequence Number : ' + str(sequence) +
          ' Acknowledgement : ' + str(acknowledgement) +
          ' TCP header length : ' + str(tcph_length))
    """
