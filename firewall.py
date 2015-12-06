#!/usr/bin/env python

from main import (
    PKT_DIR_INCOMING,
    PKT_DIR_OUTGOING,
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

def rules(filename):
    """
    Create an array of rules from the rules file specified in the firewall config.
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
                'verdict'     : rule[0],
                'protocol'    : 'dns',
                'domain_name' : rule[2],
            }
        elif rule[1] == "http":
            new_rule = {
                'verdict'   : rule[0],
                'protocol'  : 'http',
                'host_name' : rule[2],
            }
        else:
            # probably just a line of text, do nothing
            continue
        print new_rule
        rules.append(new_rule)
    return rules

def geos(filename):
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

class Packet:
    def __init__(self, pkt, pkt_dir):
        self.bytes = pkt
        self.direction = pkt_dir

        self.ip_header = IPHeader(pkt)
        self.length = self.ip_header.total_len

        assert(len(self.bytes) == self.length)  # Remove later

        protocol, header = self.determine_transport_header()
        self.transport_protocol = protocol
        self.transport_header = header

        ext_addr, ext_port, int_port = self.determine_external_address()
        self.external_address = ext_addr
        self.external_port = ext_port
        self.internal_port = int_port

        # If protocol is HTTP, application_header will store the packet payload
        protocol, header = self.determine_application_header()
        self.application_protocol = protocol
        self.application_header = header


    def determine_external_address(self):
        """
        Based on the direction of this packet and address information stored in its
        headers, return the external IP address and port number. Used only to
        simplify Packet constructor.
        """
        if self.direction == PKT_DIR_INCOMING:
            ext_addr = self.ip_header.src_addr
            ext_port = self.transport_header.src_port
            int_port = self.transport_header.dst_port
        elif self.direction == PKT_DIR_OUTGOING:
            ext_addr = self.ip_header.dst_addr
            ext_port = self.transport_header.dst_port
            int_port = self.transport_header.src_port
        else:
            print "determining addr and port; should be unreachable"

        return (ext_addr, ext_port, int_port)

    def determine_transport_header(self):
        """
        Based on information parsed from the IP header, determine the appropriate
        transport-layer header Class to use. Returns the protocol (string) and the
        header (Header Class). Used only to simplify Packet constructor.
        """
        protocol = self.ip_header.protocol
        ip_header_len = self.ip_header.length * 4

        if protocol == 1:
            protocol = 'icmp'
            header = ICMPHeader(self.bytes[ip_header_len:])
        elif protocol == 6:
            protocol = 'tcp'
            header = TCPHeader(self.bytes[ip_header_len:])
        elif protocol == 17:
            protocol = 'udp'
            header = UDPHeader(self.bytes[ip_header_len:])

        return (protocol, header)

    def determine_application_header(self):
        """
        Based on transport protocol and external port, determine the appropriate
        application-layer header Class to use, if any. Returns the protocol
        (string) and the header (Header Class). Used only to simplify Packet
        constructor.
        """
        protocol = None
        header = None

        # Note that IP and TCP header lengths are expressed in "words" (4 bytes)
        if self.transport_protocol == 'udp' and self.external_port == 53:
            protocol = 'dns'
            header = DNSHeader(self.bytes, self.ip_header.length)

        # If protocol is HTTP, header will store the packet payload
        if self.transport_protocol == 'tcp' and self.external_port == 80:
            protocol = 'http'
            # There will be no body if the packet is just a SYN or ACK
            ip = self.ip_header.length * 4
            tp = self.transport_header.length * 4
            if self.length > ip + tp:
                header = HTTPHeader(self.bytes[ip+tp:self.length], self.direction)

        return (protocol, header)

    def structify(self):
        """
        Clones the current state of the packet header fields and returns a byte-
        string representation of the packet.
        """
        ip = self.ip_header.structify()
        tp = self.transport_header.structify(self.ip_header)
        ap = ''
        if self.application_header != None:
            ap = self.application_header.structify()

        return ip + tp + ap

    def __str__(self):
        direction = ("incoming" if self.direction == 0 else "outgoing")
        int_addr = "10.0.2.15"
        int_port = self.internal_port
        ext_addr = ip_int_to_string(self.external_address)
        ext_port = self.external_port
        arrow = "<-" if self.direction == 0 else "->"
        return "%s %s %21s %s %21s" % (
            direction,
            self.transport_protocol,
            "%s:%s" % (int_addr, int_port),
            arrow,
            "%s:%s" % (ext_addr, ext_port),
        )

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


def checksum(data):
    """
    Compute a checksum for the given binary data with the given length (in bytes).
    """
    # Initialize checksum to empty 32-bit buffer
    checksum = 0x00000000

    # Append a zero byte if length is odd
    length = len(data)
    if (length & 1):
        data = data + '\x00'

    # Calculate value of 16-bit word and add to cumulative checksum
    for i in range(0, length, 2):
        word, = struct.unpack("!H", data[i:i+2])
        checksum += word

    # "Fold" 32-bit checksum into 16-bit word by adding two 16-bit halves
    return ~(checksum + (checksum >> 16)) & 0xffff


"""
Header classes used to parse fields from packet headers.
"""

class IPHeader:
    def __init__(self, pkt):
        self.length     = struct.unpack('!B', pkt[0])[0] & 0x0f

        self.total_len, = struct.unpack('!H', pkt[2:4])
        self.protocol,  = struct.unpack('!B', pkt[9])
        self._checksum, = struct.unpack('!H', pkt[10:12])
        self.src_addr   = socket.inet_ntoa(pkt[12:16])
        self.dst_addr   = socket.inet_ntoa(pkt[16:20])

        end = self.length * 4
        self.options = ""
        if self.length > 5:
            self.options = pkt[20:end]

        self.bytes = pkt[:end]

    def checksum(self):
        dst = socket.inet_aton(self.dst_addr)
        src = socket.inet_aton(self.src_addr)

        # Zero out the current checksum
        blank = struct.pack('!H', 0x0000)

        result = self.bytes[:10] + blank + src + dst + self.options

        assert len(result) == self.length * 4  # Remove later

        return checksum(result)

    def structify(self, deny_tcp=True):
        """
        Clones the current state of the packet header fields and returns a byte-
        string representation of the packet.
        """
        dst = socket.inet_aton(self.dst_addr)
        src = socket.inet_aton(self.src_addr)

        sum = struct.pack('!H', self.checksum())

        if not deny_tcp:
            dst = socket.inet_aton("169.229.49.130")

        result = self.bytes[:10] + sum + src + dst + self.options

        assert len(result) == self.length * 4  # Remove later

        return result


class TCPHeader:
    def __init__(self, header):
        self.bytes = header

        self.src_port,  = struct.unpack('!H', header[:2])
        self.dst_port,  = struct.unpack('!H', header[2:4])
        self.seq,       = struct.unpack('!I', header[4:8])
        self.ack,       = struct.unpack('!I', header[8:12])
        offset,         = struct.unpack('!B', header[12])
        self.length     = offset >> 4
        self.flags,     = struct.unpack('!B', header[13])
        self._checksum, = struct.unpack('!H', header[16:18])

        end = self.length * 4
        self.options = ""
        if self.length > 5:
            self.options = header[20:end]

    def checksum(self, ip):
        flags = struct.pack('!B', self.flags)
        dst_port = struct.pack('!H', self.dst_port)
        src_port = struct.pack('!H', self.src_port)
        ack    = struct.pack('!I', self.ack)

        # Zero out the current checksum
        blank = struct.pack('!H', 0x0000)

        tcp = src_port + dst_port + self.bytes[4:8] + ack + self.bytes[12] + flags + self.bytes[14:16] + blank + self.bytes[18:]

        # Generate pseudo IP header
        src_addr = socket.inet_aton(ip.src_addr)
        dst_addr = socket.inet_aton(ip.dst_addr)
        reserved = struct.pack('!B', 0x00)
        protocol = struct.pack('!B', ip.protocol)
        length   = struct.pack('!H', len(self.bytes))

        ip = src_addr + dst_addr + reserved + protocol + length

        return checksum(ip + tcp)


    def structify(self, ip):
        """
        Clones the current state of the packet header fields and returns a byte-
        string representation of the packet.
        """
        flags  = struct.pack('!B', self.flags)
        src    = struct.pack('!H', self.src_port)
        dst    = struct.pack('!H', self.dst_port)
        ack    = struct.pack('!I', self.ack)
        length = self.length * 4
        pkt    = self.bytes

        sum = struct.pack('!H', self.checksum(ip))

        return src + dst + pkt[4:8] + ack + pkt[12] + flags + pkt[14:16] + sum + pkt[18:length]


class UDPHeader:
    def __init__(self, header):
        self.bytes = header

        self.src_port,  = struct.unpack('!H', header[:2])
        self.dst_port,  = struct.unpack('!H', header[2:4])
        self.length,    = struct.unpack('!H', header[4:6])
        self.checksum   = struct.unpack('!H', header[6:8])

    def structify(self, ip):
        src = struct.pack("!H", self.src_port)
        dst = struct.pack("!H", self.dst_port)
        len = struct.pack("!H", self.length)
        # Decline to list checksum by zeroing these two bytes
        sum = struct.pack("!H", 0x0000)

        return src + dst + len + sum



class ICMPHeader:
    def __init__(self, header):
        self.bytes = pkt

        self.the_type, = struct.unpack('!B', header[0])
        self.code,     = struct.unpack('!B', header[1])
        self.checksum, = struct.unpack('!H', header[2:4])
        self.src_port  = 0
        self.dst_port  = 0


class DNSHeader:
    def __init__(self, pkt, ip_header_len):
        start = (ip_header_len * 4) + 8
        pkt = pkt[start:]
        self.bytes = pkt

        self.qdcount, = struct.unpack("!H", pkt[4:6])
        self.ancount, = struct.unpack("!H", pkt[6:8])
        self.qname = ""
        self.answer = ""
        self.body = pkt[12:]
        curr = 0

        # Parse for the DNS domain name in question
        if self.qdcount > 0:
            while True:
                size, = struct.unpack("!B", self.body[curr])
                curr += 1
                if size == 0:
                    break
                for i in range(size):
                    token, = struct.unpack("!c", self.body[curr])
                    self.qname += token
                    curr += 1
                self.qname += "."
            # Remove the extra period added at the end
            self.qname = self.qname[:-1]
            self.qtype, = struct.unpack("!H", pkt[curr:curr+2])
            self.qclass, = struct.unpack("!H", pkt[curr+2:curr+4])

        curr += 4
        self.question = pkt[12:curr+12]

    # Note that 'ip' is not used. This is only needed to structify TCP headers, but
    # is included so that TCPHeader and UDPHeader provide the same API
    def structify(self):
        # Set the QR field to 1
        qfields, = struct.unpack('!H', self.bytes[2:4])
        qfields  = qfields | 0x80
        # Set RCODE field to 0
        qfields  = qfields & 0xf8
        qfields  = struct.pack('!H', qfields)
        # NSCOUNT and ARCOUNT will be set to 0
        zero    = struct.pack('!H', 0x0000)
        qdcount = struct.pack('!H', self.qdcount)
        ancount = struct.pack('!H', self.ancount)

        nlength = len(self.qname) + 2
        name = self.question[:nlength]
        # TYPE = A (1)
        typ = struct.pack('!H', 0x0001)
        # CLASS = IN (1)
        cls = struct.pack('!H', 0x0001)
        ttl = struct.pack('!I', 0x00000001)
        # Convert DNS answer to packed binary
        rdata = socket.inet_aton(self.answer)
        rdlength = struct.pack('!H', len(rdata))  # len(rdata) should be 4
        header = self.bytes[:2] + qfields + qdcount + ancount + zero + zero
        
        answer = name + typ + cls + ttl + rdlength + rdata

        return header + self.question + answer


class HTTPHeader:
    def __init__(self, pkt, direction):
        # The contents of the HTTP packet in string form
        self.data = binary_to_string(pkt)
        self.bytes = pkt

        self.direction = direction

        # Fields needed for 'log' verdict
        self.host_name   = ""
        self.method      = ""
        self.path        = ""
        self.version     = ""
        self.status_code = ""
        self.object_size = -1

        self.parsed = False
        self.parse()

    @property
    def length(self):
        return len(self.data)

    def append(self, data):
        """
        Append data from another TCP packet. Re-parse fields
        """
        if not self.parsed:
            self.data += data
            self.parse()

    def parse(self):
        """
        Parse the data fields of this HTTP packet. Note that it is assumed that
        the firewall's host will only be sending HTTP requests and not responses.
        """
        # Return if a full line has not yet been sent
        if self.data.find('\r\n') == -1:
            return

        # Ignore HTTP body content (but record size)
        end = self.data.find('\r\n\r\n')
        if end >= 0:
            end += len('\r\n\r\n')
            self.data = self.data[:end]
            if not self.parsed:
                self.parsed = True

        lines = self.data.split('\r\n')
        tokens = lines[0].split(' ')

        if self.direction == PKT_DIR_OUTGOING:
            self.parse_outgoing()
        elif self.direction == PKT_DIR_INCOMING:
            self.parse_incoming()


    def parse_outgoing(self):
        # Parse fields in the first line (e.g. "GET / HTTP/1.1")
        end = self.data.find('\r\n')
        tokens = self.data[:end].split(' ')
        self.method  = tokens[0]
        self.path    = tokens[1]
        self.version = tokens[2]

        # Find "Host" field if present
        host = self.data.find("Host:")
        if host != -1:
            start = host + len("Host:")
            frag = self.data[start:]
            # Find the end of the line
            end = frag.find('\r\n')
            if end != -1:
                # Trim leading/trailing whitespace if necessary
                self.host_name = frag[:end].strip()
                self.parsed = True


    def parse_incoming(self):
        # Parse fields in the first line (e.g. "HTTP/1.1 200 OK")
        end = self.data.find('\r\n')
        tokens = self.data[:end].split(' ')
        self.version = tokens[0]
        self.status_code = tokens[1]

        # Find "Content-Length" field if present
        size = self.data.find("Content-Length:")
        if size != -1:
            start = size + len("Content-Length:")
            frag = self.data[start:]
            # Find the end of the line
            end = frag.find('\r\n')
            if end != -1:
                # Trim leading/trailing whitespace if necessary
                self.object_size = frag[:end].strip()
                self.parsed = True

    def structify(self):
        return self.bytes


def binary_to_string(binary):
    """
    Convert the given packed binary with the given length into an ASCII string.
    """
    results = ""
    for i in range(len(binary)):
        ch = struct.unpack("!c", binary[i])[0]
        results += ch
    return results
