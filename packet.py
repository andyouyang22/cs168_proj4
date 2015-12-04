
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
        self.length = self.ip_header.total_len

        assert(len(self.bytes) == self.length)  # Remove later

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
        ip_header_len = self.ip_header.length

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
            header = DNSHeader(self.bytes, self.ip_header.length)

        if self.transport_protocol == 'tcp' and self.external_port == 80:
            protocol = 'http'
            # There will be no body if the packet is just a SYN or ACK
            ip = self.ip_header.length * 4
            tp = self.transport_header.length * 4
            if self.length > ip + tp:
                header = HTTPHeader(self)

        return (protocol, header)

    def clone(self):
        """
        Clones the current state of the packet header fields and returns a byte-
        string representation of the packet.
        """
        clone = self.bytes
        ip = self.ip_header.clone()
        tp = self.transport_header.clone()

        assert len(ip) + len(tp) < self.length  # Remove later

        return ip + tp + clone[len(ip)+len(tp):]


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


def checksum(data, length):
    """
    Compute a checksum for the given binary data with the given length (in bytes).
    """
    # Initialize checksum to empty 32-bit buffer
    checksum = 0x00000000

    # Append a zero byte if length is odd
    data = data[:length]
    if (length & 1):
        data = data + '\x00'

    # Calculate value of 16-bit word and add to cumulative checksum
    for i in range(0, length, 2):
        word, = struct.unpack("!H", data[i:i+2])
        checksum += word

    # "Fold" 32-bit checksum into 16-bit word by adding two 16-bit halves
    checksum = (checksum >> 16) + (checksum & 0xffff)

    return checksum


"""
Header classes used to parse fields from packet headers.
"""

class IPHeader:
    def __init__(self, pkt):
        first, = struct.unpack('!B', pkt[0])
        first  = bin(first)

        self.length     = int(first[6:], 2)
        self.total_len, = struct.unpack('!H', pkt[2:4])
        self.protocol,  = struct.unpack('!B', pkt[9])
        self.checksum,  = struct.unpack('!H', pkt[10:12])
        self.src_addr   = socket.inet_ntoa(pkt[12:16])
        self.dst_addr   = socket.inet_ntoa(pkt[16:20])

        end = self.length * 4
        self.options = None
        if self.length > 5:
            self.options = pkt[20:end]

    def clone(self):
        """
        Clones the current state of the packet header fields and returns a byte-
        string representation of the packet.
        """



class TCPHeader:
    def __init__(self, pkt, ip_header_len):
        start = ip_header_len * 4

        self.src_port, = struct.unpack('!H', pkt[start:start+2])
        self.dst_port, = struct.unpack('!H', pkt[start+2:start+4])
        off_res,       = struct.unpack('!B', pkt[start+12])
        off_res_bits   = bin(off_res)
        self.length    = int(off_res_bits[:6], 2)
        self.checksum, = struct.unpack('!H', pkt[start+16:start+18])

        end = self.length * 4
        self.options = None
        if self.length > 5:
            self.options = pkt[start + 20 : start + end]

    def clone(self):
        """
        Clones the current state of the packet header fields and returns a byte-
        string representation of the packet.
        """


class UDPHeader:
    def __init__(self, pkt, ip_header_len):
        start = ip_header_len * 4

        self.src_port,  = struct.unpack('!H', pkt[start:start+2])
        self.dst_port,  = struct.unpack('!H', pkt[start+2:start+4])
        self.length,    = struct.unpack('!H', pkt[start+4:start+6])
        self.checksum   = struct.unpack('!H', pkt[start+6:start+8])


class ICMPHeader:
    def __init__(self, pkt, ip_header_len):
        start= ip_header_len * 4

        self.the_type, = struct.unpack('!B', pkt[start])
        self.code,     = struct.unpack('!B', pkt[start+1])
        self.checksum, = struct.unpack('!H', pkt[start+2:start+4])
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
    def __init__(self, packet):
        self.pkt = packet
    	ip = packet.ip_header.length * 4
    	tp = packet.transport_header.length * 4
        curr = ip + tp
        print "curr is %s" % curr
        print "total len is %s" % packet.length
        if packet.direction == PKT_DIR_INCOMING:
            self.log_info_incoming(packet.bytes, curr)
        else:
            self.log_info_outgoing(packet.bytes, curr)

    def log_info_incoming(self, pkt, start):
        curr = start
        self.host_name = None
        while struct.unpack("!c", pkt[curr]) + struct.unpack("!c", pkt[curr+1]) != "\r\n\r\n":
            info = ""
            while struct.unpack("!c", pkt[start])[0] != "\r\n":
                info += struct.unpack("!c", pkt[curr])[0]
                print info
            info = info.split(':')
            if len(info) == 1: ## first line
                first_line = info.split()
                self.method = first_line[0]
                self.path = first_line[1]
                self.version = first_line[2]
            elif info[0] == "Host":
                self.host_name = info[1]
            curr += 1
            print info

    def log_info_outgoing(self, pkt, start):
        curr = start
        self.object_size = -1
        while struct.unpack("!c", pkt[curr])[0] + struct.unpack("!c", pkt[curr+1])[0] != "\r\n\r\n":
            info = ""
            while struct.unpack("!c", pkt[start])[0] != "\r\n":
                info += struct.unpack("!c", pkt[curr])[0]
            info = info.split(':')
            if len(info) == 1:
                self.version = info[2]
                self.status_code = int(info[1])
            elif info[0] == "Content-Length":
                self.object_size = int(info[1])
            curr += 1
            print info


###
# Make sure there is a host_name field. From the specs:
#   "Use the value of Host request header field. If it is not present, use the
#   external IP address of the TCP connection."

# Also, if no host_name is provided in the header, set self.host_name = None
