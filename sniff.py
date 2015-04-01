# ONLY FOR LINUX !!!

# Use script only in sudo mode!!!

# You can write output of the sniff-script to file with this command:
# python sniff.py > output.txt

import datetime
import os
import socket
import struct
import sys
import time
from threading import Thread

class WebPacket:
    def __init__(self, packet):
        self.ip_unpack(packet[0:20])
        self.tcp_unpack(packet[self.iph_len:self.iph_len+20])
        self.data = packet[self.iph_len+self.tcph_len:]
        self.receipt_time = datetime.datetime.now() # Time of receipt.

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

# Make class for permanent listening connections on socket in 1st thread:
class ListenToSocket(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.web_packets = []
        self.flag = True # Sign of exit from the listening thread.

    def run(self):
        #print("AA")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.settimeout(2)
        #self.web_packets = []
        #print("AAA")

        while self.flag:
            #print("CCC")
            try:
                packet, web_addr = self.sock.recvfrom(65535)
                #print("*", end=" ")
                packet_obj = WebPacket(packet)
                self.web_packets.append(packet_obj)
            except socket.timeout:
                #time.sleep(1)
                continue
            except:
                break


# Function print all attributes of packet object:
def print_obj_items(pack):
    attrs = vars(pack)
    print(', '.join("%s: %s" % item for item in attrs.items()))
    return 1


# Function for displaying results of sniffering in 2nd thread:
def displaydata(list_of_objects):
    while True:
        print("Time: " + datetime.datetime.now().strftime("%H:%M:%S"))
        print(" q - quit\n", 
              "s - show all packets; n - show number of packets\n",
              "f - show first packet; l - show last packet\n",
              "p - pick by attribute.\n",
              "Format of command: p attribute value\n",
              "Example of syntax: p s_port 80\n",
              "Some names of attributes: s_addr, d_addr, s_port, d_port, ...\n"
            
             )
        ch = input("What do you want? ")
        print("-"*20)
        
        if ch == 's':
            if list_of_objects:
                print("All packets:")
                for pack in list_of_objects:
                    print_obj_items(pack)
            else:
                print("No packages were recieved.")
        elif ch == 'n':
            print("Number of packets: ", len(list_of_objects))
        elif ch == 'f':
            try:
                print("First packet:")
                print_obj_items(list_of_objects[0])
            except:
                print("There is no packages.")
        elif ch == 'l':
            try:
                print("Last packet:\n")
                print_obj_items(list_of_objects[-1])
            except:
                print("There is no packages.")
        elif ch[0] == 'p':
            try:
                p, attr, value = ch.split()
                packet_flag = False
                counter = 1
                for pack in list_of_objects:
                    if str(getattr(pack, attr)) == value:
                        packet_flag = True
                        print("."*20, '\n', counter, ":")
                        counter += 1
                        print_obj_items(pack)
                if not packet_flag:
                    print("There are no such packets.")
            except:
                print("Re-type your command")
        elif ch == 'q':
            sys.exit("Script was terminated.")
        else:
            print("Re-type your command")

        input("Press any key to continue...")
        os.system('clear')



if __name__ == '__main__':
    #attrs = vars(packet_obj)
    #print(datetime.datetime.now().strftime("%d-%m %H:%M:%S"))
    #print(', '.join("%s: %s" % item for item in attrs.items()))
    #print("XXX")
    t1 = ListenToSocket()  # Thread that listens to socket and parse packets.
    t1.start()
    # Thread that display data from collected and parsed packets:
    t2 = Thread(target=displaydata, args = (t1.web_packets,))
    t2.start()
    t2.join()
    t1.flag = False # Stop listening thread.
    t1.join() # Wait closure of listening thread.
    print("Script was stopped.")





