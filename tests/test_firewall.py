import unittest

from loglab.parsers.firewall import parse_firewall


class FirewallTests(unittest.TestCase):
    def test_syslog(self):
        line = "Dec 30 10:03:30 firewall-1 kernel: [12499.456] [UFW BLOCK] OUT= IN=eth0 SRC=10.0.0.5 DST=10.10.0.5 PROTO=TCP SPT=33333 DPT=22\n"
        event, = parse_firewall([line], file="firewall.log")
        self.assertEqual((event.raw_timestamp, event.timestamp, event.host), ("Dec 30 10:03:30", None, "firewall-1"))
        self.assertEqual((event.src_ip, event.dst_ip), ("10.0.0.5", "10.10.0.5"))
        self.assertEqual((event.status, event.protocol, event.src_port, event.dst_port), ("BLOCK", "TCP", 33333, 22))
        self.assertEqual(event.details["in_interface"], "eth0")
        self.assertIsNone(event.details["out_interface"])
        self.assertEqual(event.raw_message, line)

    def test_no_clock_or_ports(self):
        event, = parse_firewall(["[UFW DENY] OUT=eth1 PROTO=ICMP"], file="sample")
        self.assertEqual((event.status, event.details["out_interface"]), ("DENY", "eth1"))
        self.assertEqual((event.src_port, event.dst_port, event.raw_timestamp, event.timestamp), (None,) * 4)

    def test_invalid(self):
        lines = ["broken", "[UFW BLOCK] SRC=no-ip", "[UFW ALLOW] SPT=65536",
                 "Feb 30 10:00:00 fw kernel: [UFW ALLOW] IN=eth0"]
        for number, event in enumerate(parse_firewall(lines, file="sample"), 1):
            self.assertEqual(event.event_type, "firewall_invalid")
            self.assertIn("reason", event.details)
            self.assertEqual(event.raw_message, lines[number - 1])
