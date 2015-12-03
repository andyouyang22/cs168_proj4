
from main import (
	PKT_DIR_INCOMING,
	PKT_DIR_OUTGOING,
)
import socket
import struct

class Packet:
	def __init__(self, pkt, pkt_dir):
		self.bytes = pkt
		self.direction = pkt_dir
		self.ip_header = IPHeader(pkt)

		protocol, header = self.determine_transport_header()
		self.transport_protocol = protocol
		self.transport_header = header

		addr, port = self.determine_external_address()
		self.external_address = addr
		self.external_port = port

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
			addr = self.ip_header.src_addr
			port = int(self.transport_header.src_port)
		elif self.direction == PKT_DIR_OUTGOING:
			addr = self.ip_header.dst_addr
			port = int(self.transport_header.dst_port)
		else:
			print "determining addr and port; should be unreachable"

		return (addr, port)

	def determine_transport_header(self):
		"""
		Based on information parsed from the IP header, determine the appropriate
		transport-layer header Class to use. Returns the protocol (string) and the
		header (Header Class). Used only to simplify Packet constructor.
		"""
		protocol = self.ip_header.protocol
		ip_header_len = self.ip_header.header_len

		if protocol == 1:
			protocol = 'icmp'
			header = ICMPHeader(self.bytes, ip_header_len)
		elif protocol == 6:
			protocol = 'tcp'
			header = TCPHeader(self.bytes, ip_header_len)
		elif protocol == 17:
			protocol = 'udp'
			header = UDPHeader(self.bytes, ip_header_len)

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
			header = DNSHeader(self.bytes, self.ip_header.header_len)

		if self.transport_protocol == 'tcp' and self.external_port == 80:
			protocol = 'http'
			header = HTTPHeader(
				self.bytes,
				self.ip_header.header_len,
				self.transport_header.offset,
			)

		return (protocol, header)


	def __str__(self):
		direction = ("incoming" if self.direction == 0 else "outgoing")
		src_addr = ip_int_to_string(self.ip_header.src_addr)
		src_port = self.transport_header.src_port
		dst_addr = ip_int_to_string(self.ip_header.dst_addr)
		dst_port = self.transport_header.dst_port
		return "%s %s %20s -> %20s" % (
			direction, 
			self.transport_protocol, 
			"%s:%s" % (src_addr, src_port), 
			"%s:%s" % (dst_addr, dst_port),
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


"""
Header classes used to parse fields from packet headers.
"""

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


class HTTPHeader:
	def __init__(self, pkt, ip_header_len, tcp_header_len):
		return
		self.data = {}
		curr = (ip_header_len * 4) + (tcp_header_len * 4)
		while struct.unpack("!C", pkt[curr]) + struct.unpack("!C", pkt[curr+1]) != b("\r\n\r\n"):
			info = ""
			while struct.unpack("!B", pkt[start]) != b("\r\n"):
				info += struct.unpack("!C", pck[curr])
			info = info.split(':')
			self.data[info[0]] = info[1]
	###
	# Make sure there is a host_name field. From the specs:
	#   "Use the value of Host request header field. If it is not present, use the
	#   external IP address of the TCP connection."

	# Also, if no host_name is provided in the header, set self.host_name = None
