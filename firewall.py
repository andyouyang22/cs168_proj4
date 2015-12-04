#!/usr/bin/env python

from main import (
    PKT_DIR_INCOMING,
    PKT_DIR_OUTGOING,
)
from packet import Packet, checksum
import parse
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
        self.rules = parse.rules(config['rule'])

        # Load the GeoIP DB ('geoipdb.txt') as well.
        self.geos = parse.geos('geoipdb.txt')

        self.seq_num_to_http = {}

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
        verdict = self.verdict(packet)

        print "%6s - %s" % (verdict, packet)
        print "ip_header.checksum                = %d" % packet.ip_header.checksum
        print "checksum(bytes, ip_header.length) = %d" % checksum(packet.bytes, packet.ip_header.length)

        if verdict == 'pass':
            self.pass_packet(packet.bytes, packet.direction)

        if verdict == 'deny-tcp':
            self.denytcp_packet(packet)

        if verdict == 'deny-dns':
            self.denydns_packet(packet)

        if verdict == 'log':
            self.log_packet(packet)

    # TODO: You can add more methods as you want.

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
        if packet.direction != PKT_DIR_INCOMING:
            return

        # Set RST (0x04) and ACK (0x10) flags
        packet.transport_header.tcp_flags = 0x14

        # Swap destination and source address info to send response
        my_addr = packet.ip_header.dst_addr
        my_port = packet.transport_header.dst_port
        dst_addr = packet.ip_header.src_addr
        dst_port = packet.transport_header.src_port

        packet.ip_header.src_addr = my_addr
        packet.transport_header.src_port = my_port
        packet.ip_header.dst_addr = dst_addr
        packet.transport_header.dst_port = dst_port

        # Calculate and set the checksum fields (performed in packet.structify)

        # Convert the packet to a packed binary and send response to source
        self.pass_packet(packet.structify(), PKT_DIR_OUTGOING)

    def denydns_packet(self, packet):
        """
        Insert documentation here.
        """
        # TODO:
        # Drop 'pkt'
        # If QTYPE == "AAAA", don't send response. Be done
        # Otherwise, create DNS packet
        # Send to internal interface pointing to fixed IP addr 169.229.49.130

        # Temporary
        self.pass_packet(packet.bytes, packet.direction)

    def log_packet(self, packet):
        """
        We only want to log transactions, so we only do the log on response and
        otherwise we just store info
        """
        # Log messages should be one line and space-delimited with this format:
        # <host_name> <method> <path> <version> <status_code> <object_size>
        # e.g. google.com GET / HTTP/1.1 301 209

        # Use f.flush!

        if packet.direction == PKT_DIR_OUTGOING:
            seq_num = packet.tcp_header.seq_num
            http_header = HTTPHeader(packet)
            self.seq_num_to_http[seq_hum] = http_header
        else:
            resp_header = HTTPHeader(packet)
            req_seq_num = packet.tcp_header.seq_num - 1
            req_header = self.seq_num_to_http[req_seq_num]
            log_line = "%s %s %s %s %s %s" % (
                req_header.host_name,
                req_header.method,
                req_header.path,
                req_header.version,
                resp_header.status_code,
                resp_header.object_size
            )
            self.log_file.write(log_line)
            log_file.flush()


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
            dns = packet.application_header
            return matches_domain(rule['domain_name'], dns.domain_name)

        # Handle the case where the rule has protocol HTTP
        if protocol == 'http':
            if packet.application_protocol != 'http':
                return False
            http = packet.application_header
            if hasattr(http, 'host_name') and http.host_name != None:
                return matches_host_name(rule['host_name'], http.host_name)
            # Use external address if host name not supplied in HTTP header
            return matches_host(rule['host_name'], addr)

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
