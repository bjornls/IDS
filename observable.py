import abc


BUS = "bus"
PCAP = "pcap"

class Observable(object):

    def __init__(self, type):
        self.subscriptions = {}
        self.type = type

    def notifyModules(self, messageType, message):
        for m in self.subscriptions.get(messageType, []):
            m.publish(messageType, message)

    def subscribe(self, module):
        if self.type == BUS:
            subscr = module.busSubscr
        else:
            subscr = module.packetSubscr
        for s in subscr:
            if self.subscriptions.get(s) is None:
                self.subscriptions[s] = [module]
            else:
                self.subscriptions[s] += [module]