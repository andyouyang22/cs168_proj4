#!/usr/bin/env python

from main import (
	PKT_DIR_INCOMING,
	PKT_DIR_OUTGOING,
)
from packet import (
	Packet,
	IPHeader,
	TCPHeader,
	UDPHeader,
	ICMPHeader,
	DNSHeader,
)
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
		verdict = self.verdict(packet)

		if verdict == 'pass':
			self.pass_packet(pkt_dir, pkt)

		if verdict == 'deny-tcp':
			self.denytcp_packet(pkt_dir, pkt)

		if verdict == 'deny-dns':
			self.denydns_packet(pkt_dir, pkt)

		if verdict == 'log':
			self.log_packet(pkt_dir, pkt)

	# TODO: You can add more methods as you want.

	def pass_packet(self, pkt_dir, pkt):
		 """
		 Pass the input packet 'pkt' to the correct destination network interface
		 (INT or EXT) based on 'pkt_dir'. This code was copied from bypass.py.
		 """
		 if pkt_dir == PKT_DIR_INCOMING:
			 self.iface_int.send_ip_packet(pkt)
		 elif pkt_dir == PKT_DIR_OUTGOING:
			 self.iface_ext.send_ip_packet(pkt)

	def denytcp_packet(self, pkt_dir, pkt):
		"""
		Insert documentation here.
		"""
		# Temporary
		self.pass_packet(pkt_dir, pkt)

	def denydns_packet(self, pkt_dir, pkt):
		"""
		Insert documentation here.
		"""
		# Temporary
		self.pass_packet(pkt_dir, pkt)

	def log_packet(self, pkt_dir, pkt):
		"""
		Insert documentation here.
		"""
		# Log messages should be one line and space-delimited with this format:
		# <host_name> <method> <path> <version> <status_code> <object_size>
		# e.g. google.com GET / HTTP/1.1 301 209

		# Temporary
		self.pass_packet(pkt_dir, pkt)

	def verdict(self, packet):
		"""
		Return the appropriate verdict ('pass', 'drop', 'deny', 'log') for the
		given packet based on the rules specified in this firewall's config file.
		Note that the packet will 'pass' if it matches no rules.
		"""
		# 'drop' if the IP header doesn't have adequate length
		if packet.ip_header.header_len < 5:
			return 'drop'
		# Default to 'pass'; this is returned if 'verdict' is not overwritten
		verdict = 'pass'

		for rule in self.rules:
			if self.matches(rule, packet):
				# Record the last rule that matches the packet
				verdict = rule['verdict']

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
			if protocol != packet.transport:
				return False

		# Determine external address/port based on packet direction
		addr, port = external_address(packet)

		# Handle the case where the rule has protocol DNS
		if protocol == 'dns':
			if packet.transport != 'udp' or port != 53:
				return False
			dns = DNSHeader(packet.packet, packet.ip_header.header_len)
			return matches_domain(rule['domain_name'], dns.domain_name)

		if protocol == 'http':
			pass

		# Determine if packet external address matches rule
		if not matches_address(addr, rule, self.geos):
			return False

		# If the external address matches, determine if the port matches
		if not matches_port(port, rule):
			return False

		return True


def external_address(packet):
	"""
	Based on the direction of the given packet and address information stored in
	its headers, return the external IP address and port number.
	"""
	if packet.direction == PKT_DIR_INCOMING:
		addr = packet.ip_header.src_addr
		port = int(packet.transport_header.src_port)
	elif packet.direction == PKT_DIR_OUTGOING:
		addr = packet.ip_header.dst_addr
		port = int(packet.transport_header.dst_port)
	else:
		print "determining addr and port; should be unreachable"
	return (addr, port)


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
