## Dummy Dns server which gives responses
#!/usr/bin/env python
# coding=utf-8

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
from ip_map import ip_map

server_ip = 'localhost'

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

class DomainName(str):
        def __getattr__(self, item):
            return DomainName(item + '.' + self)

def my_match(qn1):
    i=0
    qn=qn1[:2]
    print("in mymatch", qn)
    for host_name in ip_map:
        if(qn not in host_name):
            i+=1
            continue
        print(qn)
        D = DomainName(f'{host_name}.example.com.')
        IP = ip_map[host_name]
        TTL = 60 * 5

        soa_record = SOA(
            mname=D.ns1,  # primary name server
            rname=D.andrei,  # email of the domain administrator
            times=(
                201307231+i,  # serial number
                60 * 60 * 1,  # refresh
                60 * 60 * 3,  # retry
                60 * 60 * 24,  # expire
                60 * 60 * 1,  # minimum
            )
        )
        ns_records = [NS(D.ns1), NS(D.ns2)]
        records = {
            D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
            D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
            D.ns2: [A(IP)],
            D.mail: [A(IP)],
            D.andrei: [CNAME(D)],
        }
        return soa_record, ns_records, records, TTL, D
    print("error")


def dns_response(data):
    request = DNSRecord.parse(data)
    print(request)
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    soa_record, ns_records, records, TTL, D = my_match(qn)
    for name, rrs in records.items():
        if name == qn:
            for rdata in rrs:
                rqt = rdata.__class__.__name__
                if qt in ['*', rqt]:
                    reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))

    for rdata in ns_records:
        reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

    reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    print("---- Reply:\n", reply)

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):
    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1]))
        try:
            data = self.get_data()
            print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class UDPRequestHandler(BaseRequestHandler):
    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    
    args = parser.parse_args()

    print("Starting nameserver...")

    servers = []
    servers.append(socketserver.ThreadingUDPServer((f'{server_ip}', args.port), UDPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()