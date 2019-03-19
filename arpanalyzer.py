import config


class ArpAnalyzer:
    BROADCASTING_ADDRESS = "ff:ff:ff:ff:ff:ff"

    def __init__(self, rules, refTable, arpTable):
        self.rules = rules
        self.refTable = refTable
        self.arpTable = arpTable

    def analyze(self, arpObject):
        notices = []
        errors = []
        violations = []

        if arpObject.isRequest() and self.isGratuitous(arpObject):
            violations += [self.findRule(config.Rule.RULE_GRAT)]

        if not arpObject.isRequest() and arpObject.sourceMac == ArpAnalyzer.BROADCASTING_ADDRESS:
            violations += [self.findRule(config.Rule.RULE_BRCST)]

        isStaticBinding = self.isStaticBinding(arpObject)
        if not arpObject.isRequest() and isStaticBinding:
            violations += [self.findRule(config.Rule.RULE_STATIC)]

        if not arpObject.isRequest() and self.isOverriding(arpObject) and not isStaticBinding:
            violations += [self.findRule(config.Rule.RULE_OVERRIDING)]

        for rule in violations:
            if rule is not None:
                if rule.flag == "notice":
                    notices += [rule.description]
                elif rule.flag == "error":
                    errors += [rule.description]

        return AnalysisResults(notices, errors)

    def isGratuitous(self, arpObject):
        return arpObject.senderIp == arpObject.targetIp

    def findRule(self, name):
        for rule in self.rules:
            if rule.name == name:
                return rule
        raise Exception("Could not find rule: " + name + " in config file.")

    def isOverriding(self, arpObject):
        ips = self.arpTable.keys()
        for ip in ips:
            mac = self.arpTable[ip]
            if (arpObject.senderIp == ip and mac != arpObject.sourceMac) or (
                            mac == arpObject.sourceMac and arpObject != ip):
                self.arpTable[arpObject.senderIp] = arpObject.sourceMac
                return True
            self.arpTable[arpObject.senderIp] = arpObject.sourceMac
        if len(ips) == 0:
            self.arpTable[arpObject.senderIp] = arpObject.sourceMac
        return False

    def isStaticBinding(self, arpObject):
        for entry in self.refTable:
            if ((entry.ip == arpObject.senderIp and entry.mac != arpObject.sourceMac)
                or (entry.mac == arpObject.sourceMac and entry.ip != arpObject.senderIp)):
                return True
        return False


class AnalysisResults:
    def __init__(self, notices, errors):
        self.notices = notices
        self.errors = errors
