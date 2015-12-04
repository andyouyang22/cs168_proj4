
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
                header = HTTPHeader(self.bytes[ip+tp:self.length])

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
    def __init__(self, header):
        self.bytes = header

        self.src_port, = struct.unpack('!H', header[:2])
        self.dst_port, = struct.unpack('!H', header[2:4])
        self.seq,      = struct.unpack('!I', header[4:8])
        self.ack,      = struct.unpack('!I', header[8:12])
        off_res,       = struct.unpack('!B', header[12])
        off_res_bits   = bin(off_res)
        self.length    = int(off_res_bits[:6], 2)
        self.flags,    = struct.unpack('!B', header[13])
        self.checksum, = struct.unpack('!H', header[16:18])

        end = self.length * 4
        self.options = None
        if self.length > 5:
            self.options = header[20:end]

    def clone(self):
        """
        Clones the current state of the packet header fields and returns a byte-
        string representation of the packet.
        """


class UDPHeader:
    def __init__(self, header):
        self.bytes = header

        self.src_port,  = struct.unpack('!H', header[:2])
        self.dst_port,  = struct.unpack('!H', header[2:4])
        self.length,    = struct.unpack('!H', header[4:6])
        self.checksum   = struct.unpack('!H', header[6:8])


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
    def __init__(self, pkt, direction):
        # The contents of the HTTP packet in string form
        self.data = binary_to_string(pkt)
        self.body = ""

        self.direction = direction

        # Whether or not the entire HTTP header has been received
        self.parsed = self.data.find('\r\n\r\n') != -1

        # Fields needed for 'log' verdict
        self.host_name   = ""
        self.method      = ""
        self.path        = ""
        self.version     = ""
        self.status_code = ""
        self.object_size = -1

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
            self.data = self.data[:end]
            if not self.parsed:
                self.parsed = True

        lines = self.data.split('\r\n')
        tokens = lines[0].split(' ')

        if self.direction == PKT_DIR_OUTGOING:
            self.parse_outgoing()
        else:
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


    def parse_incoming(self):
        # Parse fields in the first line (e.g. "HTTP/1.1 200 OK")
        end = self.data.find('\r\n')
        tokens = self.data[:end].split(' ')
        self.version = tokens[0]
        self.status_code = tokens[1]

        # Find "Content-Length" field if present
        size = self.data.find("Content-Length:")
        if size != -1:
            start = size + len("Content-Length")
            frag = self.data[start:]
            # Find the end of the line
            end = frag.find('\r\n')
            if end != -1:
                # Trim leading/trailing whitespace if necessary
                self.object_size = frag[:end].strip()


def binary_to_string(binary):
    """
    Convert the given packed binary with the given length into an ASCII string.
    """
    result = ""
    for i in range(len(binary)):
        ch = struct.unpack("!c", binary[i])[0]
        results += ch
    return result
