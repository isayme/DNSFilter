import os, sys
import socket
import struct
import threading
import SocketServer
import random
import json

import DTree

# config
DNSFILTER_CFG_FILE = "config.json"
DNSFILTER_CFG = {}

# dns server config
DNS_PORT = 53           # default dns port 53
TIMEOUT = 10            # set timeout 10 second, and why v2exer born with sharp eyes! 
TRY_TIMES = 3           # try to recv msg times

def ip2int(ip):
    """
    IP string to INT convert.
    """
    t = socket.inet_aton(ip)
    return struct.unpack("!I", t)[0]

def ischar(ch):
    return ord(ch) < 192 # 192 == 0xc0

# binart search, have a little changes to suit this project.
def binary_search(arr, key, lo = 0, hi = None):
    if hi is None:
        hi = len(arr)

    while lo < hi:
        mid = (lo+hi) >> 1 # equal with (lo+hi)/2
        midval = arr[mid]
        
        ipkey = key
        if 0 == (midval & 0x000000ff):  # ip format xxx.xxx.xxx.0/24
            ipkey = ipkey & 0xffffff00
        if 0 == (midval & 0x0000ff00):  # ip format xxx.xxx.0.0/16
            ipkey = ipkey & 0xffff00ff
        if 0 == (midval & 0x00ff0000):  # ip format xxx.0.0.0/8
            ipkey = ipkey & 0xff00ffff

        if midval < ipkey:
            lo = mid + 1
        elif midval > ipkey: 
            hi = mid - 1
        else:
            print "Matched with [%d.%d.%d.%d = %d.%d.%d.%d]" \
                % ((midval>> 24) & 0x00ff, (midval>> 16) & 0x00ff, (midval>> 8) & 0x00ff, (midval>> 0) & 0x00ff \
                    , (key>> 24) & 0x00ff, (key>> 16) & 0x00ff, (key>> 8) & 0x00ff, (key>> 0) & 0x00ff)
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
        if -1 != binary_search(DNSFILTER_CFG["filter_ips"], intip, 0, DNSFILTER_CFG["filter_ips_num"]):
            print "Matched ", domain
            return False

    return True
 
def QueryDNSByTCP(server, port, querydata):
    # make TCP DNS Frame
    tcp_frame = struct.pack('!h', len(querydata)) + querydata
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT) # set socket timeout
        s.connect((server, port))
        s.send(tcp_frame)
        data = s.recv(2048)
    except:
        print '[ERROR] QueryDNSByTCP: [%s:%s].' % (bytetodomain(querydata[12:])[0], e.message)
    finally:  
        if s:
            s.close()
    return data[2:]

def QueryDNSByUDP(server, port, querydata):
    data = None
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # set socket timeout
        s.settimeout(TIMEOUT)
        s.sendto(querydata, (server, port))

        for i in range(0, TRY_TIMES):
            (data, srv_addr) = s.recvfrom(1024)
            if False == IsValidPkt(data):
                #D_TREE.addDomain(bytetodomain(querydata[12:])[0])
                date = None
            else:
                break

    except Exception, e:
        print '[ERROR] QueryDNSByUDP: [%s:%s].' % (bytetodomain(querydata[12:])[0], e.message)
    finally:
        if s:
            s.close()
            
    return data

def QueryDNS(server, port, querydata):
    domain = bytetodomain(querydata[12:])[0]
    if True == DNSFILTER_CFG["filter_domains"].searchDomain(domain):
        print "TCP Query [%s]" % domain
        return QueryDNSByTCP(server, port, querydata)
    else:
        print "UDP Query [%s]" % domain
        return QueryDNSByUDP(server, port, querydata)
    
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

        dns_ip = DNSFILTER_CFG["dns_servs"][random.randint(0, DNSFILTER_CFG["dns_servs_num"] - 1)]
        #dns_ip = DNSFILTER_CFG["dns_servs"][0]

        response = QueryDNS(dns_ip, DNS_PORT, data)
        if response:
            sock.sendto(response, client_address)
        
if __name__ == "__main__":
    print "---------------------------------------------------------------"
    print "| To Use this tool, you must set your dns server to 127.0.0.1 |"
    print "---------------------------------------------------------------"

    # load config file
    f = file(DNSFILTER_CFG_FILE)
    DNSFILTER_CFG = json.load(f)
    f.close()

    # parse each para
    DNSFILTER_CFG["dns_servs_num"] = len(DNSFILTER_CFG["dns_servs"])

    DNSFILTER_CFG["filter_ips"] = []
    for item in DNSFILTER_CFG["ip_blacklist"]:
        DNSFILTER_CFG["filter_ips"].append(ip2int(item))
    DNSFILTER_CFG["filter_ips"].sort()
    DNSFILTER_CFG["filter_ips_num"] = len(DNSFILTER_CFG["filter_ips"])

    DNSFILTER_CFG["filter_domains"] = DTree.DTree()
    for item in DNSFILTER_CFG["domain_blacklist"]:
        DNSFILTER_CFG["filter_domains"].addDomain(item)
        
    #sys.exit(0)
    
    dns_server = ThreadedUDPServer(('127.0.0.1', DNS_PORT), ThreadedUDPRequestHandler)
    dns_server.serve_forever()
