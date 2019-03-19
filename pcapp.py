import observable as o

class Pcap(o.Observable):
    def __init__(self):
        super(Pcap, self).__init__(o.PCAP)