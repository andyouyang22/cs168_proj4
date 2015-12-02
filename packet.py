
class Packet:
	def __init__(self, pkt, pkt_dir):
		self.bytes = pkt
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


class HTTPHeader:
	def __init__(self, pkt, ip_header_len, tcp_header_len):
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
