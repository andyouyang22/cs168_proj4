import unittest
import firewall
from main import (
    PKT_DIR_INCOMING,
    PKT_DIR_OUTGOING,
)
import packet

class TestFirewall(unittest.TestCase):

    def setUp(self):
        config = {
            'mode' : 'firewall',
            'rule' : 'rules.conf',
        }
        iface_int = MockInterface()
        iface_ext = MockInterface()
        self.firewall = firewall.Firewall(config, iface_int, iface_ext)

    def test_matches(self):
        geos = self.firewall.geos
        rule1 = {
            'protocol' : 'udp',
            'ext_ip'   : 'any',
            'ext_port' : 'any',
        }
        rule2 = {
            'protocol' : 'udp',
            'ext_ip'   : "24.32.8.8",
            'ext_port' : "100",
        }
        rule3 = {
            'protocol' : 'udp',
            'ext_ip'   : "24.32.8.0/22",
            'ext_port' : "100-200",
        }
        packet1 = MockPacket({
            'direction' : PKT_DIR_INCOMING,
            'transport' : 'udp',
            'src_addr'  : "209.20.75.76",
            'src_port'  : "3001",
            'dst_addr'  : "10.0.2.15",
            'dst_port'  : "5432",
        })
        packet2 = MockPacket({
            'direction' : PKT_DIR_OUTGOING,
            'transport' : 'udp',
            'src_addr'  : "209.20.75.76",
            'src_port'  : "3001",
            'dst_addr'  : "24.32.8.8",
            'dst_port'  : "100",
        })
        packet3 = MockPacket({
            'direction' : PKT_DIR_OUTGOING,
            'transport' : 'udp',
            'src_addr'  : "209.20.75.76",
            'src_port'  : "3001",
            'dst_addr'  : "24.32.10.218",
            'dst_port'  : "200",
        })
        self.assertTrue(self.firewall.matches(rule1, packet1))
        self.assertTrue(self.firewall.matches(rule1, packet2))
        self.assertTrue(self.firewall.matches(rule1, packet3))
        self.assertFalse(self.firewall.matches(rule2, packet1))
        self.assertTrue(self.firewall.matches(rule2, packet2))
        self.assertFalse(self.firewall.matches(rule2, packet3))
        self.assertFalse(self.firewall.matches(rule3, packet1))
        self.assertTrue(self.firewall.matches(rule3, packet2))
        self.assertTrue(self.firewall.matches(rule3, packet3))


    def test_matches_country(self):
        geos = self.firewall.geos
        self.assertTrue(firewall.matches_country(geos, 'CA', "38.113.185.20"))
        self.assertTrue(firewall.matches_country(geos, 'CA', "216.187.70.80"))
        self.assertFalse(firewall.matches_country(geos, 'US', "38.113.185.20"))
        self.assertFalse(firewall.matches_country(geos, 'CA', "65.88.0.43"))

    def test_matches_domain(self):
        self.assertTrue(firewall.matches_domain("www.google.com", "www.google.com"))
        self.assertTrue(firewall.matches_domain("*.google.com", "www.google.com"))
        self.assertTrue(firewall.matches_domain("*", "www.google.com"))
        self.assertFalse(firewall.matches_domain("*.google.com", "google.com"))

    def test_matches_prefix(self):
        self.assertTrue(firewall.matches_prefix("127.0.0.0/8", "127.0.0.1"))
        self.assertTrue(firewall.matches_prefix("127.0.0.0/24", "127.0.0.42"))
        self.assertTrue(firewall.matches_prefix("127.0.0.1/32", "127.0.0.1"))
        self.assertTrue(firewall.matches_prefix("24.93.182.0", "24.93.182.0"))
        self.assertFalse(firewall.matches_prefix("24.93.182.0", "24.93.182.18"))
        self.assertFalse(firewall.matches_prefix("24.93.182.0/8", "25.93.182.4"))
        self.assertFalse(firewall.matches_prefix("24.93.182.0/32", "24.93.182.4"))

    def test_ip_string_to_int_no_prefix(self):
        self.assertEqual(firewall.ip_string_to_int("0.0.0.0"), 0)
        self.assertEqual(firewall.ip_string_to_int("0.0.10.5"), 2565)
        self.assertEqual(firewall.ip_string_to_int("127.0.0.1"), 2130706433)
        self.assertEqual(firewall.ip_string_to_int("255.255.255.255"), 4294967295)

    def test_ip_string_to_int_prefix(self):
        self.assertEqual(firewall.ip_string_to_int("0.0.0.0/32"), 0)
        self.assertEqual(firewall.ip_string_to_int("0.0.10.5/32"), 2565)
        self.assertEqual(firewall.ip_string_to_int("127.0.0.0/8"), 2130706432)
        self.assertEqual(firewall.ip_string_to_int("127.0.0.0/12"), 2130706432)
        self.assertEqual(firewall.ip_string_to_int("127.0.0.0/16"), 2130706432)
        self.assertEqual(firewall.ip_string_to_int("127.0.0.0/21"), 2130706432)
        self.assertEqual(firewall.ip_string_to_int("127.0.0.1/32"), 2130706433)


class MockInterface:
    def __init__(self):
        self.packets = []
    def send_ip_packet(self, pkt):
        self.packets.append(pkt)

class MockPacket(packet.Packet):
    def __init__(self, packet):
        self.direction = packet['direction']
        self.ip_header = MockIPHeader(packet)

        self.transport_protocol = packet['transport']
        self.transport_header = MockTransportHeader(packet)

        addr, port = self.determine_external_address()
        self.external_address = addr
        self.external_port = port


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
