import socket
from struct import *


sizeOf = {'H' : 2, 'I' : 4, 'B' : 1}

class ArpParser:
    def __init__(self):
        pass

    def parse(self, packet):
        eth_length = 14

        return ArpObject(eth_length, packet)

def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b

class ArpObject:

    def __str__(self):
        string = "ARP Object:"
        string += "\n\topcode = " + str(self.opCode)
        string += "\n\tdest mac = " + self.destinationMac
        string += "\n\tsrc mac = " + self.sourceMac
        string += "\n\tsender ip = " + self.senderIp
        string += "\n\tsender mac = " + self.senderMac
        string += "\n\ttarget ip = " + self.targetIp
        string += "\n\ttarget mac = " + self.targetMac
        return string

    def __init__(self, arp_start, packet):
        self.destinationMac = eth_addr(packet[0:6])
        self.sourceMac = eth_addr(packet[6:12])

        meta_data_end = arp_start + sizeOf['H']*3 + sizeOf['B']*2
        data = unpack("!HHBBH", packet[arp_start:meta_data_end])
        self.opCode = data[4]


        ptr = meta_data_end + 6
        self.senderMac = eth_addr(packet[meta_data_end:ptr])
        ptr += 4
        address = unpack("!4s", packet[meta_data_end + 6:ptr])
        self.senderIp = socket.inet_ntoa(address[0])
        ptr += 6
        self.targetMac = eth_addr(packet[meta_data_end + 10:ptr])
        ptr += 4
        address = unpack("!4s", packet[meta_data_end + 16:ptr])
        self.targetIp = socket.inet_ntoa(address[0])

    def isRequest(self):
        return self.opCode == 1


