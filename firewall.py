#!/usr/bin/env python

from main import (
    PKT_DIR_INCOMING,
    PKT_DIR_OUTGOING,
)
from packet import (
    Packet,
    HTTPHeader,
    checksum,
)
from parse import (
    rules,
    geos,
)
import socket
import struct


# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

DEFAULT_LOG = "http.log"

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # Load the firewall rules (from rule_filename) here.
        self.rules = rules(config['rule'])

        # Load the GeoIP DB ('geoipdb.txt') as well.
        self.geos = geos('geoipdb.txt')

        # Map TCP SEQ number to corresponding persistent HTTP connection data
        self.conns = {}

        # Included so that a mock log file can be stubbed in during testing
        if 'log' in config:
            self.log = open(config['log'], 'a');
        else:
            self.log = open(DEFAULT_LOG, 'a')


    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        packet = Packet(pkt, pkt_dir)
        # If the packet is an HTTP packet, assemble this packet's payload with the
        # rest of the data received from this TCP connection.
        if packet.transport_protocol == 'tcp' and packet.external_port == 80:
            # Return if the HTTP packet has a forward gap in SEQ number
            if not self.handle_http_packet(packet):
                pass

        verdict = self.verdict(packet)

        print "%-8s - %s" % (verdict, packet)

        if verdict == 'pass':
            self.pass_packet(packet.bytes, packet.direction)

        if verdict == 'deny-tcp':
            self.denytcp_packet(packet)

        if verdict == 'deny-dns':
            self.denydns_packet(packet)

        if verdict == 'log':
            self.log_packet(packet)

    # TODO: You can add more methods as you want.

    def handle_http_packet(self, packet):
        """
        Assemble TCP packets to form HTTP headers. This method is called any time
        the firewall receives an HTTP packet (protocol = TCP, port = 80). Note that
        this method does not perform any logging.

        Return False if the packet should be dropped because of a forward sequence
        gap; return True otherwise.
        """
        # Distinguish concurrent TCP connections by the internal port used
        port = packet.internal_port
        tcp  = packet.transport_header
        http = packet.application_header

        # 0x02 = SYN flag
        if tcp.flags & 0x02:
            self.handle_syn(packet)
            return True

        # We may have deleted this connection state because we already logged it
        if port not in self.conns:
            return True
        conn = self.conns[port]

        # If outgoing FIN packet, delete connection state (?)

        # General outgoing packet case
        if packet.direction == PKT_DIR_OUTGOING:
            # No need to update if we are just sending an ACK
            if tcp.seq == conn['req_seq'] and http != None:
                conn['req_seq'] = tcp.seq + http.length
                conn['req_header'].append(http.data)
            # Drop packets with forward gap in SEQ number (as per specs)
            if tcp.seq > conn['req_seq']:
                return False

        # General incoming packet case
        elif packet.direction == PKT_DIR_INCOMING:
            # No need to update if we are just receiving an ACK
            if tcp.seq == conn['res_seq'] and http != None:
                conn['res_seq'] = tcp.seq + http.length
                conn['res_header'].append(http.data)
            # Drop packets with forward gap in SEQ number (as per specs)
            if tcp.seq > conn['res_seq']:
                return False

    def handle_syn(self, packet):
        """
        Handle outgoing or incoming SYN packets by initializing connection state.
        """
        # Distinguish concurrent TCP connections by the internal port used
        port = packet.internal_port
        tcp  = packet.transport_header
        http = packet.application_header

        if port not in self.conns:
            self.conns[port] = {
                # Whether this current connection has been logged
                'logged' : False,
            }
        conn = self.conns[port]

        # If outgoing SYN packet, create TCP connection state dict
        if packet.direction == PKT_DIR_OUTGOING:
            # Next expected SEQ number to send
            conn['req_seq'] = tcp.seq + 1
            conn['req_header'] = HTTPHeader('', packet.direction)
        # If incoming SYN packet, update expected SEQ number
        elif packet.direction == PKT_DIR_INCOMING:
            # Next expected SEQ number to receive
            conn['res_seq'] = tcp.seq + 1
            conn['res_header'] = HTTPHeader('', packet.direction)


    def pass_packet(self, pkt, pkt_dir):
         """
         Pass the input packet 'pkt' to the correct destination network interface
         (INT or EXT) based on 'pkt_dir'. This code was copied from bypass.py.
         """
         if pkt_dir == PKT_DIR_INCOMING:
             self.iface_int.send_ip_packet(pkt)
         elif pkt_dir == PKT_DIR_OUTGOING:
             self.iface_ext.send_ip_packet(pkt)

    def denytcp_packet(self, packet):
        """
        Drop the packet. Respond with a TCP packet with the RST flag set to 1. This
        will prevent the sending application from sending subsequent SYN packets.
        """
        ip = packet.ip_header
        tcp = packet.transport_header

        # Set RST (0x04) and ACK (0x10) flags
        tcp.flags = 0x14

        # Swap destination and source address info to send response
        src_addr = ip.dst_addr
        src_port = tcp.dst_port
        dst_addr = ip.src_addr
        dst_port = tcp.src_port

        ip.src_addr = src_addr
        tcp.src_port = src_port
        ip.dst_addr = dst_addr
        tcp.dst_port = dst_port

        # Set ACK field to SEQ + 1
        tcp.ack = tcp.seq + 1

        b = packet.structify()
        i = ip.length * 4
        d, = struct.unpack('!B', b[i+13])

        # Convert the packet to a packed binary and send response to source
        self.pass_packet(packet.structify(), 1-packet.direction)

    def denydns_packet(self, packet):
        """
        Insert documentation here.
        """
        if packet.direction == PKT_DIR_INCOMING:
            return

        # If QTYPE == AAAA (28), don't send response. Be done
        if packet.application_header.qtype == 28:
            return

        # Otherwise, simulate DNS response from server
        ip = packet.ip_header
        tcp = packet.transport_header

        ip.src_addr = packet.external_address
        tcp.src_port = packet.external_port
        ip.dst_addr = "10.0.2.15"
        tcp.dst_port = packet.internal_port

        # Insert response record into Answer field of DNS packet
        packet.qdcount = 1
        packet.ancount = 1

        packet.application_header.answer = "169.229.49.130"

        self.pass_packet(packet.structify(), PKT_DIR_INCOMING)

    def log_packet(self, packet):
        """
        Log the given HTTP connection. Note that if a connection contains multiple
        HTTP request-response pairs, the 'req_header' and 'res_header' fields will
        be reset. This method should be called again afterwards to log this pair.
        """
        port = packet.internal_port
        if port not in self.conns:
            return
        conn = self.conns[port]

        # Return if we have already logged this connection
        if conn['logged']:
            return
        # Return if either request or response field is missing
        if 'req_header' not in conn or 'res_header' not in conn:
            return
        req = conn['req_header']
        res = conn['res_header']
        if not req.parsed and not res.parsed:
            return

        line = "%s %s %s %s %s %s\r\n" % (
            req.host_name,
            req.method,
            req.path,
            req.version,
            res.status_code,
            res.object_size
        )
        self.log.write(line)
        self.log.flush()
        print "logged -- %s" % line
        conn['logged'] = True

    def verdict(self, packet):
        """
        Return the appropriate verdict ('pass', 'drop', 'deny', 'log') for the
        given packet based on the rules specified in this firewall's config file.
        Note that the packet will 'pass' if it matches no rules.
        """
        # 'drop' if the IP header doesn't have adequate length
        if packet.ip_header.length < 5:
            return 'drop'
        # Default to 'pass'; this is returned if 'verdict' is not overwritten
        verdict = 'pass'

        for rule in self.rules:
            if self.matches(rule, packet):
                # Record the last rule that matches the packet
                verdict = rule['verdict']

        # In the case of 'deny', distinguish between 'deny-tcp' and 'deny-dns'
        if verdict == 'deny':
            return verdict + "-" + rule['protocol']

        return verdict

    def matches(self, rule, packet):
        """
        Return True if the given packet matches the given rule; return False
        otherwise.
        """
        protocol = rule['protocol']
        # DNS and HTTP have special cases handled below
        if protocol != 'dns' and protocol != 'http':
            # If protocol == TCP, UDP, or ICMP:
            if protocol != packet.transport_protocol:
                return False

        # Determine external address/port based on packet direction
        addr = packet.external_address
        port = packet.external_port

        # Handle the case where the rule has protocol DNS
        if protocol == 'dns':
            if packet.application_protocol != 'dns':
                return False
            if packet.direction == PKT_DIR_INCOMING:
                return False

            dns = packet.application_header

            # Return False if DNS packet does not contain exactly one question
            if dns.qdcount != 1:
                return False
            # # Return False if DNS packet does not have QTYPE == A (1) or AAAA (28)
            # if dns.qtype not in [1, 28]:
            #     return False
            # # Return False if DNS packet does not have QCLASS == INTERNET (1)
            # if dns.qclass != 1:
            #     return False
            return matches_domain(rule['domain_name'], dns.qname)

        # Handle the case where the rule has protocol HTTP
        if protocol == 'http':
            if packet.application_protocol != 'http':
                return False
            if packet.internal_port in self.conns:
                conn = self.conns[packet.internal_port]
                if 'req_header' in conn:
                    http = conn['req_header']
                    if http.host_name != "":
                        return matches_host_name(rule['host_name'], http.host_name)
            # Use external address if host name not supplied in HTTP header
            return matches_host_name(rule['host_name'], addr)

        # If both exteral address and port match the target, return True
        if matches_address(addr, rule, self.geos):
            if matches_port(port, rule):
                return True
        return False


"""
Helper functions for matching against an IP address.
"""

def matches_address(addr, rule, geos):
    """
    Return True if the given address 'addr' matches the external IP address
    specified in the given rule, provided the given geographical IP mapping;
    return False otherwise.
    """
    if rule['ext_ip'] == 'any':
        return True
    elif len(rule['ext_ip']) == 2: # Country code
        return matches_country(geos, rule['ext_ip'], addr)
    else:
        return matches_prefix(rule['ext_ip'], addr)


def matches_port(port, rule):
    """
    Return True if the given port number 'port' matches the external port specified
    in the given rule; return False otherwise.
    """
    if rule['ext_port'] == 'any':
        return True
    endpoints = rule['ext_port'].split('-')
    if len(endpoints) == 2:
        start = int(endpoints[0])
        end = int(endpoints[1])
        return start <= port and port <= end
    elif len(endpoints) == 1:
        return int(endpoints[0]) == port
    else:
        print "matching port; should be unreachable"


def matches_country(geos, code, addr):
    """
    Return True if the given address falls within a the given country's IP
    address range; return False otherwise.
    """
    if len(geos) == 0:
        return False

    code = code.lower()
    mid = geos[len(geos)/2]
    mid_start = ip_string_to_int(mid['start_ip']) # midpoint as 32-bit int
    a = ip_string_to_int(addr) # address in question as 32-bit int

    if len(geos) == 1:
        mid_end = ip_string_to_int(mid['end_ip'])
        return a >= mid_start and a <= mid_end and code == mid['country_code']
    elif a < mid_start:
        return matches_country(geos[:len(geos)/2], code, addr)
    else:
        return matches_country(geos[len(geos)/2:], code, addr)


def matches_domain(target, addr):
    """
    Return True if the given addr falls under the given target domain name
    pattern (e.g. target = "*.berkeley.edu"); return false otherwise.
    """
    if len(target) == 0:
        return False
    if target[0] != "*":
        return target == addr
    else:
        return target[1:] == addr[len(addr)-len(target)+1:]


def matches_host_name(target, addr):
    """
    Return True if the given addr falls under the given target host name. This
    target can be a domain name or a single IP address.
    """
    if target == "*":
        return True
    if target == addr:
        return True
    if matches_domain(target, addr):
        return True
    return False


def matches_prefix(prefix, addr):
    """
    Return True if the given address falls within the given prefix; return False
    otherwise.
    """
    addr = addr if type(addr) == int else ip_string_to_int(addr)
    net = ip_string_to_int(prefix)
    prefix = prefix.split('/')

    shift = 0
    if len(prefix) == 2:
        shift = 32 - int(prefix[1])
    return (addr >> shift) == (net >> shift)



"""
Helper functions for converting between dotted quad IP addresses and 32-bit ints.
"""

def ip_string_to_int(ip, prefix=32):
    """
    Convert the given IP address from dotted quad to 32-bit int.
    """
    if type(ip) == int or type(ip) == long:
        return ip
    ip = ip.split('/')[0]
    b = ip.split('.')
    for i in range(4):
        b[i] = int(b[i])
    return (((((b[0] * 256) + b[1]) * 256) + b[2]) * 256) + b[3]
