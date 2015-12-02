import unittest
import firewall
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

class TestFirewall(unittest.TestCase):

	def setUp(self):
		config = {
			'mode' : 'firewall',
			'rule' : 'rules.conf',
		}
		iface_int = MockInterface()
		iface_ext = MockInterface()
		self.firewall = firewall.Firewall(config, iface_int, iface_ext)

	def test_verdict_domain_full(self):
		self.firewall.rules = [
			rules['log-domain-full'],
		]
		self.assertEquals(self.firewall.verdict())


class MockInterface:
	def __init__(self):
		self.packets = []
	def send_ip_packet(self, pkt):
		self.packets.append(pkt)

class MockPacket:
	def __init__(self, packet):
		self.direction = packet['direction']
		self.ip_header = MockIPHeader(packet)
		self.transport = packet['transport']
		self.transport_header = MockTransportHeader(packet)

class MockIPHeader:
	def __init__(self, packet):
		self.src_addr = packet['src_addr']
		self.dst_addr = packet['dst_addr']

class MockTransportHeader:
	def __init__(self, packet):
		self.src_port = packet['src_port']
		self.dst_port = packet['dst_port']

class MockHTTPHeader:
	def __init__(self, packet):
		return


rule_log_domain_full = {
	'verdict'   : 'log',
	'protocol'  : 'http',
	'host_name' : 'google.com',
}
rule_log_domain_wildcard = {
	'verdict'   : 'log',
	'protocol'  : 'http',
	'host_name' : '*.facebook.com',
}
rule_log_ip_addr = {
	'verdict'   : 'log',
	'protocol'  : 'http',
	'host_name' : '123.45.67.89',
}
rule_log_all = {
	'verdict'   : 'log',
	'protocol'  : 'http',
	'host_name' : '*',
}

packet_http = MockPacket({
	'direction' : PKT_DIR_INCOMING,
	'transport' : 'tcp',
	'src_addr'  : "209.20.75.76",
	'src_port'  : "80",
	'dst_addr'  : "10.0.2.15",
	'dst_port'  : "5432",
})


if __name__ == '__main__':
	unittest.main()
