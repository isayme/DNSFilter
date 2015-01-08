import os, sys
import socket
import struct
import threading
import SocketServer
import random
import json

import threadpool

# config
DNSFILTER_CFG = {}

# dns server config
TIMEOUT = 5            # set timeout 5 second
TRY_TIMES = 3           # try to recv msg times

def ip2int(ip):
    """
    IP string to INT convert.
    """
    t = socket.inet_aton(ip)
    return struct.unpack('!I', t)[0]

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
            print 'Matched with [%d.%d.%d.%d = %d.%d.%d.%d]' \
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

def is_valid_pkt(response):
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
        if -1 != binary_search(DNSFILTER_CFG['filter_ips'], intip, 0, DNSFILTER_CFG['filter_ips_num']):
            return False

    return True

class ThreadPoolMixIn:
    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
            self.shutdown_request(request)
        except:
            self.handle_error(request, client_address)
            self.shutdown_request(request)

    def process_request(self, request, client_address):
        self.tp.add_task(self.process_request_thread, request, client_address)

    def serve_forever(self, poll_interval=0.5):
        try:
            SocketServer.UDPServer.serve_forever(self, poll_interval)
        finally:
            self.tp.stop()
            

class DNSFilter(ThreadPoolMixIn, SocketServer.UDPServer):
    # much faster rebinding
    allow_reuse_address = True
    
    def __init__(self, s, t):        
        self.tp = threadpool.ThreadPool(20)
        SocketServer.UDPServer.__init__(self, s, t)
  
  
class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        query_data = self.request[0]
        udp_sock = self.request[1]
        addr = self.client_address

        dns_ip = DNSFILTER_CFG['dns_servs'][random.randint(0, DNSFILTER_CFG['dns_servs_num'] - 1)]
        response = self.dns_query(dns_ip, 53, query_data)
        if response:
            # udp dns packet no length
            udp_sock.sendto(response, addr)
 
    def dns_query(self, dns_ip, dns_port, query_data):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5) # set socket timeout = 5s
        
            s.sendto(query_data, (dns_ip, dns_port))
            
            for i in xrange(TRY_TIMES):
                data, addr = s.recvfrom(1024)
                if False == is_valid_pkt(data):
                    date = None
                else:
                    break
            
        except:
            return None
        finally:
            if s: s.close()

        return data
    
    
if __name__ == '__main__':
    print '---------------------------------------------------------------'
    print '| To Use this tool, you must set your dns server to 127.0.0.1 |'
    print '---------------------------------------------------------------'

    # load config file
    f = file('config.json')
    DNSFILTER_CFG = json.load(f)
    f.close()

    # parse each para
    DNSFILTER_CFG['dns_servs_num'] = len(DNSFILTER_CFG['dns_servs'])

    DNSFILTER_CFG['filter_ips'] = []
    for item in DNSFILTER_CFG['ip_blacklist']:
        DNSFILTER_CFG['filter_ips'].append(ip2int(item))
    DNSFILTER_CFG['filter_ips'].sort()
    DNSFILTER_CFG['filter_ips_num'] = len(DNSFILTER_CFG['filter_ips'])

    
    dns_server = DNSFilter(('0.0.0.0', 53), ThreadedUDPRequestHandler)
    dns_server.serve_forever()
