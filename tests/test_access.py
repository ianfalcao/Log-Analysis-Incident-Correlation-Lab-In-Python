import unittest

from loglab.parsers.access import parse_access


class AccessTests(unittest.TestCase):
    def test_combined(self):
        line = '::1 - - [30/Dec/2025:10:00:00 -0300] "GET /a?q=b HTTP/1.1" 200 0 "-" "Example Agent"\r\n'
        event, = parse_access([line], file="access.log")
        self.assertEqual(event.to_dict()["timestamp"], "2025-12-30T13:00:00+00:00")
        self.assertEqual((event.src_ip, event.protocol, event.status), ("::1", "HTTP/1.1", 200))
        self.assertEqual(event.details, dict(path="/a?q=b", method="GET", response_bytes=0, user_agent="Example Agent"))
        self.assertEqual(event.raw_message, line)

    def test_partial(self):
        prefix = '127.0.0.1 - - [30/Dec/2025:10:00:00 +0000] "GET /" - '
        numbered, missing = parse_access([prefix + "408", prefix + "-"], file="access.log")
        self.assertEqual(numbered.details["response_bytes"], 408)
        self.assertIsNone(numbered.status)
        self.assertIsNone(numbered.protocol)
        self.assertNotIn("response_bytes", missing.details)
        self.assertNotIn("user_agent", missing.details)

    def test_invalid(self):
        for line in ["broken", '::1 - - [bad date] "GET /" 200 1',
                     '::1 - - [30/Dec/2025:10:00:00 +0000] "GET" 200 1']:
            with self.subTest(line=line):
                event, = parse_access([line], file="access.log")
                self.assertEqual(event.event_type, "access_invalid")
                self.assertIn("reason", event.details)
                self.assertEqual(event.raw_message, line)
