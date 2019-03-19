import xml.etree.ElementTree
import abc
import pcapp as p
import bus as b
import module as mod

class Config:
    def __init__(self, name):
        self.__modules = {}
        self.pcap = p.Pcap()
        self.bus = b.Bus()

        e = xml.etree.ElementTree.parse(name).getroot()

        self.__modules[mod.Module.ERROR] = mod.Module(self.pcap, self.bus, mod.Module.ERROR, [], [])

        for m in e.find('modules').findall('module'):
            moduleName = m.find('name').text

            packetSubscr = m.find('subscriptions').find('packets').text
            if packetSubscr is not None:
                packetSubscr = (packetSubscr).split(",")
                packetSubscr = list(map(lambda x: x.strip(), packetSubscr))
            else:
                packetSubscr = []

            busSubscr = m.find('subscriptions').find('bus').text
            if busSubscr is not None:
                busSubscr = (busSubscr).split(",")
                busSubscr = list(map(lambda x: x.strip(), busSubscr))
            else:
                busSubscr = []


            if moduleName == mod.DaiModule.NAME:
                attributes = self.parseDaiModule(m)
                module = mod.DaiModule(self.pcap, self.bus, packetSubscr, busSubscr, attributes)

            elif moduleName == mod.TestModule.NAME:
                module = mod.TestModule(self.pcap, self.bus, mod.TestModule.NAME, packetSubscr, busSubscr)

            else:
                raise Exception("Error in config, module is not supported: " + moduleName)

            self.__modules[moduleName] = module

    def getModule(self, name):
        return self.__modules[name]

    def parseDaiModule(self, m):
        refTable = []
        rules = []

        for entry in m.find('reference-table').findall('entry'):
            type = entry.find('type').text
            ip = entry.find('ip').text
            mac = entry.find('mac').text
            refTable += [Entry(type, ip, mac)]

        for rule in m.find('rules').findall('rule'):
            name = rule.find('name').text
            desc = rule.find('description').text
            flag = rule.find('flag').text
            rules += [Rule(name, desc, flag)]

        return {mod.DaiModule.RULES : rules, mod.DaiModule.REF_TABLE : refTable}


class Rule:

    FLAG_ERROR = "error"
    FLAG_NOTICE = "notice"
    FLAG_PERMITTED = "permitted"

    RULE_GRAT = "gratuitous"
    RULE_BRCST = "response-from-broadcasting"
    RULE_OVERRIDING = "overriding-existing-binding"
    RULE_STATIC = "static-binding"

    def __init__(self, name, description, flag):
        self.name = name
        self.description = description
        self.flag = flag


class Entry:
    def __init__(self, type, ip, mac):
        self.type = type
        self.ip = ip
        self.mac = mac

