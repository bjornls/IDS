#from __future__ import absolute_import
import unittest
import module as m
import pcapy as p
import config as c
import arpparser as ap

class TestArpAnalyzer(unittest.TestCase):

    def testErrorHandlingWhenRuleIsMissing(self):
        arpPacket = Packets("gratuitous.pcap", False).getPackets()[0]
        conf = c.Config('conf-error.xml')

        conf.pcap.notifyModules("ARP", arpPacket)
        result = conf.getModule(m.TestModule.NAME).latestMsg
        errormsg = "Error when parsing ARP object"
        self.assertEquals(result[0:len(errormsg)], errormsg)

    def testMacUpdateInArpTable(self):
        arpPackets = Packets("mac-update.pcap", False).getPackets()
        conf = c.Config('conf.xml')

        conf.pcap.notifyModules("ARP", arpPackets[0])
        result = conf.getModule(m.TestModule.NAME).latestMsg
        self.assertEquals(len(result.notices), 0)
        self.assertEquals(len(result.errors), 0)

        conf.pcap.notifyModules("ARP", arpPackets[1])

        result = conf.getModule(m.TestModule.NAME).latestMsg

        self.assertEquals(result.notices[0], 'Response triggers an update of an entry in the ARP table')

    def testIpUpdateInArpTable(self):
        arpPackets = Packets("ip-update.pcap", False).getPackets()
        conf = c.Config('conf.xml')

        conf.pcap.notifyModules("ARP", arpPackets[0])
        result = conf.getModule(m.TestModule.NAME).latestMsg
        self.assertEquals(len(result.notices), 0)
        self.assertEquals(len(result.errors), 0)

        conf.pcap.notifyModules("ARP", arpPackets[1])

        result = conf.getModule(m.TestModule.NAME).latestMsg

        self.assertEquals(result.notices[0], 'Response triggers an update of an entry in the ARP table')

    def testAttemptToModifyStaticEntry(self):
        arpPacket = Packets("static-violation.pcap", False).getPackets()[0]
        conf = c.Config('conf.xml')

        conf.pcap.notifyModules("ARP", arpPacket)

        result = conf.getModule(m.TestModule.NAME).latestMsg

        self.assertEquals(result.errors[0], 'Binding belongs to a static ARP table')

    def testBroadcastingAsSourceMacIsAnError(self):
        arpPacket = Packets("brcast_error.pcap", False).getPackets()[0]
        conf = c.Config('conf.xml')

        conf.pcap.notifyModules("ARP", arpPacket)

        result = conf.getModule(m.TestModule.NAME).latestMsg

        self.assertEquals(result.errors[0], "Response was from the broadcasting address which will cause host to broadcast all messages sent to IP address")

    def testGratuitous(self):
        arpPacket = Packets("gratuitous.pcap", False).getPackets()[0]
        conf = c.Config('conf.xml')

        conf.pcap.notifyModules("ARP", arpPacket)

        result = conf.getModule(m.TestModule.NAME).latestMsg

        self.assertEquals(result.notices[0], "Response was triggered without a request")


class TestConfigReader(unittest.TestCase):
    def testConfig(self):
        config = c.Config('conf.xml')

        daiModule = config.getModule('DAI')
        self.assertEquals(type(daiModule), m.DaiModule)
        self.assertEquals(daiModule.packetSubscr, ["ARP"])
        self.assertEquals(daiModule.busSubscr, [])

        testModule = config.getModule('TEST')
        self.assertEquals(type(testModule), m.TestModule)
        self.assertEquals(testModule.packetSubscr, [])
        self.assertEquals(testModule.busSubscr, ["DAI", "error"])

        self.assertEquals(daiModule.refTable[0].type, "switch")
        self.assertEquals(daiModule.refTable[0].ip, "145.94.212.11")
        self.assertEquals(daiModule.refTable[0].mac, "a1:b2:c3:d4:e5:f6")

        self.assertEquals(daiModule.refTable[1].type, "official")
        self.assertEquals(daiModule.refTable[1].ip, "145.94.212.99")
        self.assertEquals(daiModule.refTable[1].mac, "aa:bb:cc:dd:ee:ff")

        self.assertEquals(daiModule.rules[0].name, "static-binding")
        self.assertEquals(daiModule.rules[0].description, "Binding belongs to a static ARP table")
        self.assertEquals(daiModule.rules[0].flag, "error")




class TestDesign(unittest.TestCase):

    def testParsingResponse(self):
        packet = Packets("arpsample.pcap", False).getPackets()[1]

        self.assertEquals(packet.isRequest(), False)
        self.assertEquals(packet.senderMac, "00:00:0c:07:ac:01")
        self.assertEquals(packet.senderIp, "145.94.212.1")
        self.assertEquals(packet.targetMac, "68:a8:6d:2c:9c:fe")
        self.assertEquals(packet.targetIp, "145.94.215.222")


class Packets:
    def __init__(self, pcapFile, raw):
        arpParser = ap.ArpParser()
        self.__arpPackets = []

        cap = p.open_offline(pcapFile)
        (header, packet) = cap.next()

        while header is not None:
            if raw:
                self.__arpPackets += [packet]
            else:
                self.__arpPackets += [arpParser.parse(packet)]
            (header, packet) = cap.next()

    def getPackets(self):
        return self.__arpPackets
