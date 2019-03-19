import socket
from struct import *

pointers = {}
codes = {1:'A (1)', 2:'NS (2)', 5:'CNAME (5)', 6:'SOA (6)', 12:'PTR (12)', 15:'MX (15)', 16:'TXT (16)',
         #28 : "AAAA (28)"
         255:'* (255)'}
sizeOf = {'H' : 2, 'I' : 4, 'B' : 1}

class DnsParser:

    def __init__(self):
        pass

    def parse(self, packet):
        # parse ethernet header
        eth_length = 14
        udp_length = 8

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        print 'Destination MAC : ' + self.eth_addr(packet[0:6]) + ' Source MAC : ' + self.eth_addr(
            packet[6:12]) + ' Protocol : ' + str(eth_protocol)

        # fetch the length of ip header to determine where the DNS starts
        ip_header = packet[eth_length:20 + eth_length]
        iph = unpack('!B', ip_header[:1])
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        dns_header_start = eth_length + iph_length + udp_length
        dns_header_end = 2*6

        dns_packet = packet[dns_header_start:]

        dnsObject = DnsObject()

        dns_header_tuple = unpack("!HHHHHH", dns_packet[:dns_header_end])
        dns_header = DnsHeader(dns_header_tuple)
        dnsObject.set_header(dns_header)

        start = dns_header_end

        util = Util()

        for _ in range (dns_header.questions):
            dnsQuery = DnsQuery(start, dns_packet, util)
            start = dnsQuery.dns_query_end
            dnsObject.add_query(dnsQuery)

        for _ in range(dns_header.answers_rr):
            dnsAnswer = DnsAnswer(start, dns_packet, "DNS Answer", util)
            start = dnsAnswer.dns_answer_end
            dnsObject.add_answer(dnsAnswer)

        for _ in range(dns_header.auth_rr):
            dnsAnswer = DnsAnswer(start, dns_packet, "Authoritative Name Server", util)
            start = dnsAnswer.dns_answer_end
            dnsObject.add_auth_name_server(dnsAnswer)

        for _ in range(dns_header.add_rr):
            dnsAnswer = DnsAnswer(start, dns_packet, "Additional Record", util)
            start = dnsAnswer.dns_answer_end
            dnsObject.add_add_records(dnsAnswer)

        return dnsObject

    @staticmethod
    def eth_addr(a):
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
        return b

class DnsObject:
    def __init__(self):
        self.__dnsHeader = ""
        self.__dnsQueries = []
        self.__dnsAnswers = []
        self.__dnsAuthNameServers = []
        self.__dnsAddRecords = []

    def __str__(self):
        string = str(self.__dnsHeader)
        for i in range(len(self.__dnsQueries)):
            string += "\n" + str(self.__dnsQueries[i])
        for i in range(len(self.__dnsAnswers)):
            string += "\n" + str(self.__dnsAnswers[i])
        return string + "\n****EOM****\n"

    def set_header(self, dnsHeader):
        self.__dnsHeader = dnsHeader

    def add_query(self, dnsQuery):
        self.__dnsQueries += [dnsQuery]

    def add_answer(self, dnsAnswer):
        self.__dnsAnswers += [dnsAnswer]

    def add_auth_name_server(self, authNameServer):
        self.__dnsAuthNameServers += [authNameServer]

    def add_add_records(self, addRecord):
        self.__dnsAddRecords += [addRecord]


class DnsAnswer:
    def __str__(self):
        string = self.response_type + "\n\t"
        string += "Name = " + self.hostname
        if self.success:
            string += "\n\tType = " + codes[self.typecode]
            string += "\n\tClass = " + str(self.clazz) + "\n\t" + "Time to live = " + str(self.ttl) + "\n\tData length = " + str(self.length) + "\n\t" + self.typestring
        else:
            string += "\n\tError = " + self.errormsg
        return string

    def __init__(self, dns_query_start, packet, response_type, util):
        self.response_type = response_type
        self.dqs = dns_query_start
        self.packet = packet
        self.typestring = ""
        self.success = True
        self.hostnameLength = 0
        self.errormsg = ""

        metadata = util.getMetaData(dns_query_start, packet, False)

        self.hostname = metadata[0]
        self.typecode = metadata[1]
        self.clazz = metadata[2]
        self.ttl = metadata[3]
        self.length = metadata[4]
        self.std_data_end = metadata[5]

        self.dns_answer_end = self.std_data_end + self.length
        if codes.get(self.typecode) is None:
            self.errormsg = "Type Code " + str(self.typecode) + " is not supported"
            self.success = False
            return

        if self.typecode == 15: # MX
            data = unpack("!H" + str(self.length - 2) + "s", self.packet[self.std_data_end:self.dns_answer_end])
            preference = data[0]
            mailEx = util.replacePointers(data[1], packet)
            pointers[self.std_data_end + 2] = mailEx
            self.attributes = {"preference" : preference, "mailEx" : mailEx}
            self.typestring = "Preference = " + str(preference) + "\n\tMail Exchange = " + mailEx

        elif self.typecode == 5: #CNAME
            cname = unpack("!" + str(self.length) + "s", self.packet[self.std_data_end:self.dns_answer_end])[0]
            cname = util.replacePointers(cname, packet)
            pointers[self.std_data_end] = cname
            self.attributes = {"CName": cname}
            self.typestring = "CNAME = " + cname

        elif self.typecode == 12: #PTR
            ptrname = unpack("!" + str(self.length) + "s", self.packet[self.std_data_end:self.dns_answer_end])[0]
            ptrname = util.replacePointers(ptrname, packet)
            pointers[self.std_data_end] = ptrname
            self.attributes = {"PTRDNAME": ptrname}
            self.typestring = "PTRDNAME = " + ptrname

        elif self.typecode == 2: #NS
            nameserver = unpack("!" + str(self.length) + "s", self.packet[self.std_data_end:self.dns_answer_end])[0]
            nameserver = util.replacePointers(nameserver, packet)
            pointers[self.std_data_end] = nameserver
            self.attributes = {"Name Server": nameserver}
            self.typestring = "Name Server = " + nameserver

        elif self.typecode == 1: #A
            address = unpack("!4s", self.packet[self.std_data_end:self.dns_answer_end])
            self.attributes = {"Address": address}
            self.typestring = "Name Server = " + socket.inet_ntoa(address[0])

        # elif self.typecode == 28: #AAAA
        #     aaaa = unpack("!HHHH6BH", self.packet[self.std_data_end:self.dns_answer_end])
        #     aaaa_address = hex(aaaa[0])[2:] + ":" + hex(aaaa[1])[2:] + ":" + hex(aaaa[2])[2:] + ":" + hex(aaaa[3])[2:]
        #     aaaa_address += "::" + hex(aaaa[10])[2:]
        #     self.attributes = {"aaaa address" : aaaa_address}
        #     self.typestring = "AAAA Address = " + aaaa_address

        elif self.typecode == 16: #TXT
            data = unpack("!B" + str(self.length - 1) + "s", self.packet[self.std_data_end:self.dns_answer_end])
            txt_length = data[0]
            txt = data[1]
            self.attributes = {"TXT length" : txt_length, "TXT" : txt}
            self.typestring = "TXT length = " + str(txt_length) + "\n\tTXT = " + txt

        elif self.typecode == 6:  # SOA
            ramailboxLength = self.length - 5*4 - 2
            data = unpack("!BB"+str(ramailboxLength)+"siiiii", self.packet[self.std_data_end:self.dns_answer_end])
            pns = util.parseName(data[1], packet)[0]
            mailBox = util.replacePointers(data[2], packet)
            serial = data[3]
            refresh = data[4]
            retry = data[5]
            expire = data[6]
            minTtl = data[7]
            self.attributes = {"Primary name server" : pns, "Responsible authority's mailbox" : mailBox,
                               "Serial Number" : serial, "Refresh Interval" :refresh, "Retry Interval" :retry,
                               "Expire Limit" :expire, "Minimum TTL" :minTtl }
            typestring = "Primary name server = " + pns+ "\n\tResponsible authority's mailbox = " + mailBox
            typestring += "\n\tSerial Number = " + str(serial) + "\n\tRefresh Interval = " +str(refresh)+ "\n\tRetry Interval = " +str(retry)
            typestring += "\n\tExpire Limit = " + str(expire) + "\n\tMinimum TTL = " + str(minTtl)
            self.typestring = typestring



class DnsQuery:
    def __init__(self, dns_query_start, packet, util):
        self.dqs = dns_query_start
        self.packet = packet

        metadata = util.getMetaData(dns_query_start, packet, True)

        self.hostname = metadata[0]
        self.typecode = codes[metadata[1]]
        self.clazz = str(metadata[2])
        self.dns_query_end = metadata[3]

    def __str__(self):
        return "DNS Query:\n\tHostname= " + self.hostname + "\n\tType code = " + self.typecode + "\n\tClass = " + self.clazz

class DnsHeader:

    qr_code = {0: "0 : query", 1 : "1 : response"}
    op_code = {0: "0 : standard query (QUERY)", 1 : "1 : inverse query (IQUERY)", 2 : "2 : server status request (STATUS)"}
    aa_code = {0: "0 : server is not an authority for the domain name", 1:"1 : server is an authority for the domain name"}
    tc_code = {0: "0 : message was not truncated", 1: "1 : message was truncated"}
    rd_code = {0: "0 : recursion is not desired", 1: "1 : recursion is desired"}
    ra_code = {0: "0 : recursion is not allowed", 1: "1 : recursion is allowed"}
    r_code  = {0: "0 : No error condition", 1: "1 : Format error", 2: "2 : Server failure",
               3: "3 : Name Error", 4: "4 : Not Implemented", 5: "5 : Refused"}


    def __init__(self, dns):

        self.transid = str(dns[0])

        binary = format(dns[1], 'b').zfill(16)

        self.qr     = self.qr_code[int(binary[0], 2)]
        self.opcode = self.op_code[int(binary[1:4], 2)]
        self.aa     = self.aa_code[int(binary[5], 2)]
        self.tc     = self.tc_code[int(binary[6], 2)]
        self.rd     = self.rd_code[int(binary[7], 2)]
        self.ra     = self.ra_code[int(binary[8], 2)]
        self.rcode  = self.r_code[int(binary[12:], 2)]

        self.questions = dns[2]
        self.answers_rr = dns[3]
        self.auth_rr = dns[4]
        self.add_rr = dns[5]


    def __str__(self):
        string = "DNS Header:\n\tTransaction Id = " + self.transid + "\n\t\tQR = " + self.qr + "\n\t\tOP = " + self.opcode + "\n\t\tAA = " + self.aa
        string += "\n\t\tTC = " + self.tc + "\n\t\tRD = " + self.rd + "\n\t\tRA = " + self.ra + "\n\t\tRCode = " + self.rcode
        string += "\n\tQuestions = " + str(self.questions) + "\n\tAnswer RRs = " + str(self.answers_rr) + "\n\tAuthority RRs = " + str(self.auth_rr)
        string += "\n\tAddition RRs = " + str(self.add_rr)
        return string


class Util:
    # retrives the first attributes: Name, Type, Class and TTL(for answers)
    def getMetaData(self, ptr, packet, isQuery):
        [name, ptr] = self.parseName(ptr, packet)
        if isQuery:
            fmt = "!HH" #H is unsigned short which is two bytes
            adv = sizeOf['H'] * 2
            ptr += 1  # skip over the terminating character
        else:
            fmt = "!HHIH" #I is unsigned integer
            adv = sizeOf['H'] * 3 + sizeOf['I']
        data = unpack(fmt, packet[ptr:ptr + adv])
        return [name] + list(data) + [ptr + adv]

    #fetches a string from the packet up until the terminating character '0'
    #ptr = integer that points to the location of label within the packet
    def parseName(self, ptr, packet):
        #save the original pointer to use as index for cache
        orig = ptr

        #in case the pointer jumps.
        # variable to preserve the length of the name (which is orig + 2 in case of a pointer)
        saved = -1

        c = ord(packet[ptr])
        if c == 0:
            return ["<root>", ptr]
        elif c < 32:  # skip over bit specifying the length
            ptr += 1
            c = ord(packet[ptr])
        result = ""

        #iterate over each character
        while c != 0:
            if self.isPointer(c):
                cache = pointers.get(ord(packet[ptr + 1]))
                if cache is None:
                    saved = ptr
                    ptr = ord(packet[ptr+1]) #jump
                    c = ord(packet[ptr])
                else:
                    if len(result) != 0:
                        result += "."
                    result += cache
                    return [result, ptr + 2]
            else: #it is a label
                if c < 32: #condition if character is a length-bit. replace it with a dot
                    result += "."
                else:
                    result += chr(c)
                ptr += 1
                c = ord(packet[ptr])

        pointers[orig] = result #cache
        if saved != -1:
            ptr = saved + 2 #length of the location the pointer points to is irrelevant
        return [result, ptr]

    #the function takes a string and replaces all instances of pointers with the label
    def replacePointers(self, string, packet):
        tmp = string
        result = ""
        isPointer = False
        for i in range(len(tmp)):
            o = ord(tmp[i])
            if i == 0 and o < 32: #skips over the length bit
                continue
            if isPointer:
                if i > 0:
                    result += "."
                result += self.parseName(ord(tmp[i]), packet)[0]
                isPointer = False
            elif self.isPointer(o):
                isPointer = True
            elif o < 32:
                result += "."
            else:
                result += tmp[i]
        return result


    @staticmethod
    def isPointer(name):
        return format(name, 'b').zfill(8)[0:2] == '11'
