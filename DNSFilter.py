import os
import sys
import socket
import struct
import SocketServer

import threadpool

# fake ip list
FAKE_IPLIST = {}

# dns server config
TIMEOUT = 2             # set timeout 2 second
TRY_TIMES = 5           # try to recv msg times
DNS_SERVER = '8.8.8.8'  # remote dns server

# currently not used
def bytetodomain(s):
    domain = ''
    i = 0
    
    length = struct.unpack('!B', s[0:1])[0]
    while length != 0:
        i += 1
        domain += s[i:i + length]
        i += length
        length = struct.unpack('!B', s[i:i+1])[0]
        if length != 0:
            domain += '.'

    return (domain, i + 1)

def skip_query(query):
    step = 0
    
    length = struct.unpack('!B', query[0:1])[0]
    while length != 0:
        step = step + length + 1
        length = struct.unpack('!B', query[step:step+1])[0]

    return step + 1

def is_valid_pkt(response):
    try:
        (flag, qdcount, ancount) = struct.unpack('!HHH', response[2:8])
        
        if flag != 0x8180 and flag != 0x8580:
            return True

        if 1 != qdcount or 1 != ancount:
            return True
        
        dlen = skip_query(response[12:])
        pos = 12 + dlen
        
        (qtype, qclass) = struct.unpack('!HH', response[pos:pos+4])
        # qtype is 1 (mean query HOST ADDRESS), qclass is 1 (mean INTERNET)
        if 1 != qtype or 1 != qclass:
            return True
        
        pos = pos + 4 # position for response
        if ord(response[pos:pos+1]) & 0xc0:
            pos = pos + 12
        else:
            pos = pos + dlen + 10

        if response[pos:pos+4] in FAKE_IPLIST:
            print('Match: ' + socket.inet_ntoa(response[pos:pos+4]))
            return False
    except Exception, e:
        print(e)

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

        response = self.dns_query(DNS_SERVER, 53, query_data)
        if response:
            # udp dns packet no length
            udp_sock.sendto(response, addr)
 
    def dns_query(self, dns_ip, dns_port, query_data):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(TIMEOUT) # set socket timeout = 5s
        
            s.sendto(query_data, (dns_ip, dns_port))
            
            for i in xrange(TRY_TIMES):
                data, addr = s.recvfrom(1024)
                if is_valid_pkt(data):
                    return data
                else:
                    data = None
            
        except:
            return None
        finally:
            if s: s.close()

        return data
    
if __name__ == '__main__':
    print '---------------------------------------------------------------'
    print '| To Use this tool, you must set your dns server to 127.0.0.1 |'
    print '---------------------------------------------------------------'

    # load config file, iplist.txt from https://github.com/clowwindy/ChinaDNS
    with open('iplist.txt', 'rb') as f:
        while 1:
            ip = f.readline()
            if ip:
                FAKE_IPLIST[socket.inet_aton(ip[:-1])] = None
            else:
                break
    
    dns_server = DNSFilter(('0.0.0.0', 53), ThreadedUDPRequestHandler)
    try:
        dns_server.serve_forever()
    except:
        pass
    finally:
        pass
                
