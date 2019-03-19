import abc
import arpanalyzer as aa

class Module(object):
    ERROR = "error"
    def __init__(self, pcap, bus, name, packetSubscr, busSubscr):
        self.NAME = name
        self.packetSubscr = packetSubscr
        self.busSubscr = busSubscr
        self.bus = bus
        pcap.subscribe(self)
        bus.subscribe(self)

    @abc.abstractmethod
    def publish(self, messageType, message):
        pass

class DaiModule(Module):
    NAME = "DAI"
    RULES = "rules"
    REF_TABLE = "refTable"

    def publish(self, messageType, message):
        try:
            daiResults = aa.ArpAnalyzer(self.rules, self.refTable, self.arpTable).analyze(message)
            self.bus.notifyModules(DaiModule.NAME, daiResults)
        except Exception, e:
            msg = "Error when parsing ARP object: \n" + str(message)
            msg += "\n\nError ="
            msg += str(e)

            self.bus.notifyModules(Module.ERROR, msg)

    def __init__(self, pcap, bus, packetSubscr, busSubscr, attributes):
        super(DaiModule, self).__init__(pcap, bus, DaiModule.NAME, packetSubscr, busSubscr)
        self.rules = attributes.get(DaiModule.RULES, [])
        self.refTable = attributes.get(DaiModule.REF_TABLE, [])
        self.requestHistory = []
        self.arpTable = {}

class TestModule(Module):
    NAME = "TEST"

    def publish(self, msgType, msg):
        self.latestMsg = msg
        self.bus.notifyModules(self.name, msg)

    def __init__(self, pcap, bus, name, packetSubscr, busSubscr):
        super(TestModule, self).__init__(pcap, bus, name, packetSubscr, busSubscr)
        self.latestMsg = None
        self.name = name