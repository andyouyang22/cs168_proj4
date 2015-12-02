#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct


# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # Load the firewall rules (from rule_filename) here.
        self.rules = self.parse_rules(config['rule'])

        # Load the GeoIP DB ('geoipdb.txt') as well.
        self.geos = self.parse_geos('geoipdb.txt')

    def parse_rules(self, filename):
        """
        Create an array of rules from the rules file specified in the firewall
        config.
        """
        rules = []
        rule_file = open(filename)
        for rule in rule_file:
            rule = rule.split()
            if len(rule) < 1:
                continue
            for i in range(len(rule)):
                rule[i] = rule[i].lower()
            if rule[0] == '%':
                continue
            if rule[1] == "tcp" or rule[1] == "udp" or rule[1] == "icmp":
                new_rule = {
                    'verdict'  : rule[0],
                    'protocol' : rule[1],
                    'ext_ip'   : rule[2],
                    'ext_port' : rule[3],
                }
            elif rule[1] == "dns":
                new_rule = {
                    'verdict'  : rule[0],
                    'protocol' : 'dns',
                    'domain_name' : rule[2],
                }
            else:
                # probably just a line of text, do nothing
                continue
            print new_rule
            rules.append(new_rule)
        return rules

    def parse_geos(self, filename):
        """
        Create an array of geographical IP mappings from the GeoIP file specified.
        """
        geos = []
        geo_file = open(filename)
        for geo_line in geo_file:
            geo_line = geo_line.split()
            for i in range(len(geo_line)):
                geo_line[i] = geo_line[i].lower()
            new_geo = {
                'start_ip'     : geo_line[0],
                'end_ip'       : geo_line[1],
                'country_code' : geo_line[2],
            }
            geos.append(new_geo)
        return geos

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        packet = Packet(pkt, pkt_dir)
        if self.should_pass(packet):
            self.pass_packet(pkt_dir, pkt)

    # TODO: You can add more methods as you want.

    def should_pass(self, packet):
        """
        Return True if the given packet should be passed (rather than dropped)
        based on the rules specified in this firewall's config file; return False
        otherwise.
        """
        if packet.ip_header.header_len < 5:
            return False
        match = None
        for rule in self.rules:
            if self.matches(rule, packet):
                # Choose the last rule that matches the packet
                match = rule
        if match == None or match['verdict'] == 'pass':
            return True
        return False

    def pass_packet(self, pkt_dir, pkt):
         """
         Pass the input packet 'pkt' to the correct destination network interface
         (INT or EXT) based on 'pkt_dir'. This code was copied from bypass.py.
         """
         if pkt_dir == PKT_DIR_INCOMING:
             self.iface_int.send_ip_packet(pkt)
         elif pkt_dir == PKT_DIR_OUTGOING:
             self.iface_ext.send_ip_packet(pkt)


    def matches(self, rule, packet):
        """
        Return True if the given packet matches the given rule; return False
        otherwise.
        """
        protocol = rule['protocol']
        if protocol != packet.transport and protocol != 'dns':
            return False

        # Determine external address/port based on packet direction
        if packet.direction == PKT_DIR_INCOMING:
            addr = packet.ip_header.src_addr
            port = int(packet.transport_header.src_port)
        elif packet.direction == PKT_DIR_OUTGOING:
            addr = packet.ip_header.dst_addr
            port = int(packet.transport_header.dst_port)
        else:
            print "determining addr and port; should be unreachable"

        # Handle the case where the rule has protocol DNS
        if protocol == 'dns':
            if packet.transport != 'udp' or port != 53:
                return False
            dns = DNSHeader(packet.packet, packet.ip_header.header_len)
            return matches_domain(rule['domain_name'], dns.domain_name)

        # Determine if packet external address matches rule
        addr_match = False
        print rule
        if rule['ext_ip'] == 'any':
            addr_match = True
        elif len(rule['ext_ip']) == 2: # Country code
            addr_match = matches_country(self.geos, rule['ext_ip'], addr)
        else:
            addr_match = matches_prefix(rule['ext_ip'], addr)

        if not addr_match:
            return False

        # If the external address matches, determine if the port matches
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


def ip_int_to_string(ip):
    """
    Convert the given IP address from 32-bit int to dotted quad.
    """
    if type(ip) == str:
        return ip
    b = [0, 0, 0, 0]
    for i in range(4):
        b[3-i] = ip % 256
        ip /= 256
    return "%s.%s.%s.%s" % (b[0], b[1], b[2], b[3])


class Packet:
    def __init__(self, pkt, pkt_dir):
        self.packet = pkt
        self.direction = pkt_dir
        self.ip_header = IPHeader(pkt)
        protocol = self.ip_header.protocol
        ip_header_len = self.ip_header.header_len
        if protocol == 1:
            self.transport = 'icmp'
            self.transport_header = ICMPHeader(pkt, ip_header_len)
        elif protocol == 6:
            self.transport = 'tcp'
            self.transport_header = TCPHeader(pkt, ip_header_len)
        elif protocol == 17:
            self.transport = 'udp'
            self.transport_header = UDPHeader(pkt, ip_header_len)

    def __str__(self):
        direction = ("incoming" if self.direction == 0 else "outgoing")
        src_addr = ip_int_to_string(self.ip_header.src_addr)
        src_port = self.transport_header.src_port
        dst_addr = ip_int_to_string(self.ip_header.dst_addr)
        dst_port = self.transport_header.dst_port
        src = "%s:%s" % (src_addr, src_port)
        dst = "%s:%s" % (dst_addr, dst_port)
        return "%s %s %20s -> %20s" % (direction, self.transport, src, dst)


class IPHeader:
    def __init__(self, pkt):
        first,          = struct.unpack('!B', pkt[0])
        first           = bin(first)
        ip_frag_bits    = bin(struct.unpack('!H', pkt[6:8])[0])
        if ip_frag_bits == "0b0":
            ip_frag_bits = "0b0000000000000000"

        self.version    = int(first[2:6], 2)
        self.header_len = int(first[6:], 2)
        self.tos,       = struct.unpack('!B', pkt[1])
        self.total_len, = struct.unpack('!H', pkt[2:4])
        self.ident,     = struct.unpack('!H', pkt[4:6])
        self.ip_flags   = int(ip_frag_bits[:5], 2)
        self.frag       = int(ip_frag_bits[5:], 2)
        self.ttl,       = struct.unpack('!B', pkt[8])
        self.protocol,  = struct.unpack('!B', pkt[9])
        self.checksum,  = struct.unpack('!H', pkt[10:12])
        #struct.unpack('!L', pkt[12:16])
        #struct.unpack('!L', pkt[16:20])
        self.src_addr   = socket.inet_ntoa(pkt[12:16])
        self.dst_addr   = socket.inet_ntoa(pkt[16:20])
        end             = self.header_len * 4
        self.options = None
        if self.header_len > 5:
            self.options = pkt[20:end]


class TCPHeader:
    def __init__(self, pkt, ip_header_len):
        start           = ip_header_len * 4
        self.src_port,  = struct.unpack('!H', pkt[start:start+2])
        self.dst_port,  = struct.unpack('!H', pkt[start+2:start+4])
        self.seq_num,   = struct.unpack('!L', pkt[start+4:start+8])
        self.ack_num,   = struct.unpack('!L', pkt[start+8:start+12])

        off_res,        = struct.unpack('!B', pkt[start+12])
        off_res_bits    = bin(off_res)
        self.offset     = int(off_res_bits[:6], 2)
        self.reserved   = int(off_res_bits[6:], 2)

        self.tcp_flags, = struct.unpack('!B', pkt[start+13])
        self.window,    = struct.unpack('!H', pkt[start+14:start+16])
        self.checksum,  = struct.unpack('!H', pkt[start+16:start+18])
        self.urgent_pointer, = struct.unpack('!H', pkt[start+18:start+20])
        end             = self.offset * 4
        self.options    = None
        if self.offset > 5:
           self.options = pkt[start + 20 : start + end]


class UDPHeader:
    def __init__(self, pkt, ip_header_len):
        start           = ip_header_len * 4
        self.src_port,  = struct.unpack('!H', pkt[start:start+2])
        self.dst_port,  = struct.unpack('!H', pkt[start+2:start+4])
        self.length,    = struct.unpack('!H', pkt[start+4:start+6])
        self.checksum   = struct.unpack('!H', pkt[start+6:start+8])


class ICMPHeader:
    def __init__(self, pkt, ip_header_len):
        start          = ip_header_len * 4
        self.the_type, = struct.unpack('!B', pkt[start])
        self.code,     = struct.unpack('!B', pkt[start+1])
        self.checksum, = struct.unpack('!H', pkt[start+2:start+4])
        self.other,    = struct.unpack('!L', pkt[start+4:start+8])
        self.src_port  = 0
        self.dst_port  = 0


class DNSHeader:
    def __init__(self, pkt, ip_header_len):
        start = (ip_header_len * 4) + 8
        self.qdcount = struct.unpack("!H", pkt[start+4:start+6])
        self.ancount = struct.unpack("!H", pkt[start+6:start+8])

        self.domain_name = ""
        curr = start + 12
        while True:
            size, = struct.unpack("!B", pkt[curr])
            curr += 1
            if size == 0:
                break
            for i in range(size):
                token, = struct.unpack("!c", pkt[curr])
                self.domain_name += token
                curr += 1
            self.domain_name += "."
        self.domain_name = self.domain_name[:-1]
        self.qtype = struct.unpack("!H", pkt[curr:curr+2])
