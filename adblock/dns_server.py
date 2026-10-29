"""DNS server: answers blocked names with 0.0.0.0 / ::, forwards everything else upstream."""

import logging

from dnslib import AAAA, A, QTYPE, RCODE, RR, DNSRecord
from dnslib.server import BaseResolver, DNSLogger, DNSServer

log = logging.getLogger(__name__)

BLOCK_TTL = 60


class BlockingResolver(BaseResolver):
    def __init__(self, filter_, upstreams, timeout=3.0):
        self.filter = filter_
        self.upstreams = upstreams
        self.timeout = timeout

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE.get(request.q.qtype, str(request.q.qtype))
        client_ip = handler.client_address[0]
        blocked, reason = self.filter.check(qname, client_ip)
        self.filter.record(qname, client_ip, qtype, blocked, reason)
        if blocked:
            return self._blocked_reply(request)
        return self._forward(request, handler.protocol == "tcp")

    def _blocked_reply(self, request):
        reply = request.reply()
        if request.q.qtype == QTYPE.A:
            reply.add_answer(RR(request.q.qname, QTYPE.A, ttl=BLOCK_TTL, rdata=A("0.0.0.0")))
        elif request.q.qtype == QTYPE.AAAA:
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, ttl=BLOCK_TTL, rdata=AAAA("::")))
        # Other record types get an empty NOERROR answer.
        return reply

    def _forward(self, request, tcp):
        for host, port in self.upstreams:
            try:
                raw = request.send(host, port, tcp=tcp, timeout=self.timeout)
                return DNSRecord.parse(raw)
            except Exception as exc:  # timeouts, refused, malformed replies
                log.debug("upstream %s:%s failed: %s", host, port, exc)
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply


def start_dns(filter_, config):
    resolver = BlockingResolver(filter_, config.upstreams, config.upstream_timeout)
    quiet = DNSLogger(log="-request,-reply,-truncated,-error,-recv,-send,-data", prefix=False)
    servers = [
        DNSServer(resolver, address=config.dns_addr, port=config.dns_port, logger=quiet),
        DNSServer(resolver, address=config.dns_addr, port=config.dns_port, tcp=True, logger=quiet),
    ]
    for server in servers:
        server.start_thread()
    log.info("DNS listening on %s:%d (udp+tcp), upstreams %s",
             config.dns_addr, config.dns_port, config.upstreams)
    return servers
