import observable as o
import module as m

class Bus(o.Observable):
    def __init__(self):
        super(Bus, self).__init__(o.BUS)

    def notifyModules(self, messageType, message):
        self.logMessage(messageType, message)
        super(Bus, self).notifyModules(messageType, message)

    def logMessage(self, messageType, message):
        if messageType == m.DaiModule.NAME:
            if len(message.notices) == 0 and len(message.errors) == 0:
                print "ARP is permitted"
                return
            for notice in message.notices:
                print notice
            for error in message.errors:
                print error
        if messageType == m.Module.ERROR:
            print message
