import config as c
import dnsparser as dp
import arpparser as ap
import pcapy as p
import socket
import sys
from struct import *

pcapFiles = ["arpdump.pcap", "arpsample.pcap", "brcast_error.pcap", "gratuitous.pcap", "ip-update.pcap", "mac-update.pcap", "static-violation.pcap"]

def main():

    if len(sys.argv) < 2:
        print "Missing parameters."
        print "For live capturing: python <config file>"
        print "For reading pcap files: python <config file> <.pcap file>"
	sys.exit()

    config = c.Config(sys.argv[1])

    dump = False
    live = len(sys.argv) < 3

    if live:
        devices = p.findalldevs()
        for i in range(len(devices)):
            print str(i) + ": " + devices[i]
        letsgo = False
        while not letsgo:
            try:
                dev = int(raw_input("Choose capturing device: \n"))
                print "Listening to: " + devices[dev]
                cap = p.open_live(devices[dev], 65536, 1, 0)
                letsgo = True
            except:
                print "hmmm, try again"
    else:
        cap = p.open_offline(sys.argv[2])

    if dump:
        dumper = cap.dump_open("cap.pcap")

    #Two ways to filter only for tcp packets is to put the string "tcp" as argument in the function call below
    #Another way is to filter tcp ports, by using either port X (like below) or port range X-Y
    bpf = p.BPFProgram("arp")

    while 1:

        (header, packet) = cap.next()
        if header is None and not live:
            break
        #print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
        pi = PacketIdentifier(packet)

        f = bpf.filter(packet)
        if f != 0:
            try:
                if pi.isDns():
                    dnsObject = dp.DnsParser().parse(packet)
                    print dnsObject
                elif pi.isArp():
                    arpObject = ap.ArpParser().parse(packet)
                    config.pcap.notifyModules("ARP", arpObject)
                   # print arpObject
                else:
                    print "Unsupported protocol: " + pi.eth_protocol

            except Exception, e:
                print e

        if dump:
            dumper.dump(header, packet)


class PacketIdentifier:
    def __init__(self, packet):
        eth_length = 14
        udp_length = 8

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        self.eth_protocol = socket.ntohs(eth[2])

    def isDns(self):
        return self.eth_protocol == 8

    def isArp(self):
        return self.eth_protocol == 1544



if __name__ == "__main__":
    main()
