import os, sys
import socket
import struct
import threading
import SocketServer
import random
import json

# DNS Server List
DNS_SERVS = []
DNS_SERVS_NUM = 0

# Filter List
FILTER_IPS = []
FILTER_IPS_NUM = 0
FILTER_IPSETS = []
FILTER_IPSETS_NUM = 0

CFG_FILE = "config.json"


DNS_PORT = 53           # default dns port 53
TIMEOUT = 5             # set timeout 5 second
TRY_TIMES = 3           # try to recv msg times

def ip2int(ip):
    t = socket.inet_aton(ip)
    return struct.unpack("!I", t)[0]

def ischar(ch):
    return ord(ch) < 192 # 192 == 0xc0
   
def binary_search(arr, key, lo = 0, hi = None):
    if hi is None:
        hi = len(arr)

    while lo < hi:
        mid = (lo+hi) >> 1 # equal with (lo+hi)/2
        midval = arr[mid]
        if midval < key:
            lo = mid+1
        elif midval > key: 
            hi = mid
        else:
            return mid
    return -1

def bytetodomain(s):
    domain = ''
    i = 0
    
    length = struct.unpack('!B', s[0:1])[0]
    while length != 0:
        i += 1
        domain += s[i:i + length]
        i += length
        length = struct.unpack('!B', s[i:i + 1])[0]
        if length != 0:
            domain += '.'

    return (domain, i - 1)

def IsValidPkt(response):
    (flag, qdcount, ancount) = struct.unpack('!HHH', response[2:8])

    # response pkt & standard query & no error
    # bflag = (flag & 0x8000) and (not (flag & 0x7800)) and (not (flag & 0x000f))
    bflag = (flag & 0x8000) and (not (flag & 0x780f))

    
    if bflag and 1 == qdcount: # and 1 == ancount:
        (domain, dlen) = bytetodomain(response[12:])

        pos = 14 + dlen  # position for qtype & qclass
        (qtype, qclass) = struct.unpack('!HH', response[pos:pos+4])
        # qtype is 1 (mean query HOST ADDRESS), qclass is 1 (mean INTERNET)
        if 1 != qtype or 1 != qclass:
            return True
        
        pos = pos + 4 # position for response
        if True == ischar(response[pos:pos+1]):
            pos = pos + dlen + 2 + 10
        else:
            pos = pos + 12

        intip = struct.unpack('!I', response[pos:pos+4])[0]
        #for item in FILTER_IPS:
        #    if intip == item:
        #        print "Matched ", domain
        #        return False
        if -1 != binary_search(FILTER_IPS, intip, 0, FILTER_IPS_NUM):
            print "Matched ", domain
            return False

        if -1 != binary_search(FILTER_IPSETS, intip & 0xffffff00, 0, FILTER_IPSETS_NUM):
            print "Set Matched ", domain
            return False
        #for item in FILTER_IPSETS:
        #    if (intip & 0xffffff00) == item:
        #        print "Set Matched ", domain
        #        return False
    return True
    
def QueryDNS(server, port, querydata):
    data = None
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # set socket timeout
        s.settimeout(TIMEOUT)
        s.sendto(querydata, (server, port))

        for i in range(1, TRY_TIMES + 1):
            (data, srv_addr) = s.recvfrom(1024)
            if False == IsValidPkt(data):
                date = None
            else:
                break

    except Exception, e:
        print '[ERROR] QueryDNS: [%s:%s].' % (bytetodomain(querydata[12:])[0], e.message)
    finally:
        if s:
            s.close()

        return data

class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    # Ctrl-C will cleanly kill all spawned threads
    daemon_threads = True
    
    def __init__(self, s, t):
        SocketServer.UDPServer.__init__(self, s, t)

class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        sock = self.request[1]
        client_address = self.client_address

        dns_ip = DNS_SERVS[random.randint(0, DNS_SERVS_NUM - 1)]
        #dns_ip = DNS_SERVS[0]

        response = QueryDNS(dns_ip, DNS_PORT, data)
        if response:
            sock.sendto(response, client_address)
        
if __name__ == "__main__":
    print "---------------------------------------------------------------"
    print "| To Use this tool, you must set your dns server to 127.0.0.1 |"
    print "---------------------------------------------------------------"

     # load config file
    f = file(CFG_FILE)
    cfg = json.load(f)
    f.close()

    # parse each page
    for ip in cfg["dns_servers"]:
        DNS_SERVS.append(ip)
    DNS_SERVS.sort()
    DNS_SERVS_NUM = len(DNS_SERVS)

    for ip in cfg["filter_ips"]:
        FILTER_IPS.append(ip2int(ip))
    FILTER_IPS.sort()
    FILTER_IPS_NUM = len(FILTER_IPS)

    for ip in cfg["filter_ipsets"]:
        FILTER_IPSETS.append(ip2int(ip))
    FILTER_IPSETS.sort()
    FILTER_IPSETS_NUM = len(FILTER_IPSETS)
    #sys.exit(0)
    
    dns_server = ThreadedUDPServer(('127.0.0.1', DNS_PORT), ThreadedUDPRequestHandler)
    dns_server.serve_forever()

