import unittest
import firewall
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

class TestFirewall(unittest.TestCase):

	def setUp(self):
		config = {}
		config['mode'] = 'firewall'
		config['rule'] = 'rules.conf'
		iface_int = MockInterface()
		iface_ext = MockInterface()
		self.firewall = firewall.Firewall(config, iface_int, iface_ext)

	def test_general(self):
		return


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


if __name__ == '__main__':
	unittest.main()
