# ONLY FOR LINUX !!!

# Use script only in sudo mode!!!

# You can write output of the sniff-script to file with this command:
# python sniff.py > output.txt

import socket
import struct
import datetime

class Web_packet:
    def __init__(self, packet):
        self.ip_unpack(packet[0:20])
        self.tcp_unpack(packet[self.iph_len:self.iph_len+20])
        self.data = packet[self.iph_len+self.tcph_len:]

    def ip_unpack(self, ip_header):
        iph_unpacked = struct.unpack('!BBHHHBBH4s4s', ip_header)
        vers_and_ihl = iph_unpacked[0]
        self.version = vers_and_ihl >> 4 # Version of protocol
        self.ihl = vers_and_ihl & 0xF # Internet header length
        self.iph_len = self.ihl * 4
        self.ttl = iph_unpacked[5]
        self.protocol = iph_unpacked[6]
        self.s_addr = socket.inet_ntoa(iph_unpacked[8])
        self.d_addr = socket.inet_ntoa(iph_unpacked[9])
        return 1

    def tcp_unpack(self, tcp_header):
        tcph_unpacked = struct.unpack('!HHLLBBHHH', tcp_header)
        self.s_port = tcph_unpacked[0]
        self.d_port = tcph_unpacked[1]
        self.tcph_len = tcph_unpacked[4] >> 4
        return 1

if __name__ == '__main__':
    # create socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    web_packets = []

    while True:
        packet, web_addr = sock.recvfrom(65535)
        packet_obj = Web_packet(packet)
        print("\n"+"="*30)
        web_packets.append(packet_obj)
        attrs = vars(packet_obj)
        print(datetime.datetime.now().strftime("%d-%m %H:%M:%S"))
        print(', '.join("%s: %s" % item for item in attrs.items()))



