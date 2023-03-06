#!/usr/bin/env python3
import dnslib.server
from dnslib.server import DNSServer
from dnslib.dns import RR


class MockResolver(dnslib.server.BaseResolver):
    def resolve(self, request, _handler):
        resp = {
            'direct.test.': '127.0.0.1',
            'http.test.': '127.0.0.1',
            'socks.test.': '127.0.0.1',
            'shadowsocks.test.': '127.0.0.1',
            'trojan.test.': '127.0.0.1',
            'wireguard.test.': '127.0.0.1',
        }
        reply = request.reply()
        for q in request.questions:
            q = str(q.qname)
            print(f'request: {q}')
            if q in resp or q + '.' in resp:
                reply.add_answer(*RR.fromZone(f'{q} 60 A 127.0.0.1'))
        return reply


if __name__ == '__main__':
    server = DNSServer(resolver=MockResolver(), port=8853, address='0.0.0.0')
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    server.stop()
