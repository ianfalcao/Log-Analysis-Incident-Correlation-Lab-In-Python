import unittest
from collections import Counter
from pathlib import Path

from loglab.models import Event
from loglab.parsers.auth import parse_auth, parse_auth_line


def ssh(body):
    return parse_auth_line(f"Dec 30 10:01:15 my-server sshd[12101]: {body}\n",
                           file="auth.log", line_number=7)


class AuthParserTests(unittest.TestCase):
    def test_success(self):
        event = ssh("Accepted publickey for user dev_ops from 172.17.0.1 port 22 ssh2: RSA SHA256:abc")
        self.assertIsInstance(event, Event)
        self.assertEqual((event.source, event.event_type, event.status),
                         ("auth", "ssh_publickey_success", "success"))
        self.assertEqual((event.user, event.src_ip, event.src_port, event.protocol),
                         ("dev_ops", "172.17.0.1", 22, "ssh2"))
        self.assertEqual((event.host, event.details["pid"]), ("my-server", 12101))
        self.assertEqual(event.raw_timestamp, "Dec 30 10:01:15")
        self.assertIsNone(event.timestamp)

    def test_failed_and_invalid_user(self):
        event = ssh("Failed password for invalid user visitor from 10.0.0.5 port 48765 ssh2")
        self.assertEqual((event.event_type, event.user, event.status),
                         ("ssh_password_failed", "visitor", "failed"))
        self.assertIs(event.details["invalid_user"], True)
        standalone = ssh("Invalid user jsmith from 198.51.100.2 port 60123")
        self.assertEqual(standalone.event_type, "ssh_invalid_user")
        self.assertEqual(standalone.src_port, 60123)
        self.assertIsNone(standalone.status)

    def test_optional_fields(self):
        event = ssh("input_userauth_request: invalid user jsmith [preauth]")
        self.assertEqual((event.user, event.event_type), ("jsmith", "ssh_invalid_user"))
        for field in ("src_ip", "src_port", "dst_ip", "dst_port", "protocol"):
            self.assertIsNone(getattr(event, field))
        self.assertIsNone(ssh("Failed password for root from client.local").src_ip)

    def test_invalid_and_unrecognized_preserved(self):
        lines = ["broken\r\n", "Dec 30 10:25:05 my-server useradd[14250]: new user: name=temp_user\n",
                 "Feb 31 12:00:00 my-server sshd: hello\n"]
        events = list(parse_auth(iter(lines), file="input/auth.log"))
        self.assertEqual(Counter(e.event_type for e in events),
                         {"auth_invalid": 2, "auth_unrecognized": 1})
        for number, event in enumerate(events, 1):
            self.assertEqual((event.file, event.line_start, event.line_end, event.raw_message),
                             ("input/auth.log", number, number, lines[number - 1]))
        self.assertIn("reason", events[0].details)
        self.assertEqual(events[1].details["process"], "useradd")
        self.assertEqual(ssh("Failed password for root from ::1 port 99999").event_type, "auth_invalid")

    def test_lab_records(self):
        path = Path(__file__).resolve().parents[1] / "logs" / "auth.log"
        with path.open(encoding="utf-8") as stream:
            events = list(parse_auth(stream, file=str(path)))
        by_line = {e.line_start: e for e in events}
        self.assertEqual(by_line[1].event_type, "ssh_password_success")
        self.assertEqual(by_line[5].event_type, "login_success")
        self.assertEqual(by_line[9].event_type, "pam_failure_summary")
        self.assertEqual(by_line[9].details["reported_failures"], 2)
        self.assertEqual(by_line[10].event_type, "pam_auth_failure")
        sudo = by_line[14]
        self.assertEqual((sudo.event_type, sudo.user, sudo.details["target_user"], sudo.details["command"]),
                         ("sudo_command", "test_user", "root", "/usr/bin/apt-get update"))
        self.assertEqual(by_line[15].event_type, "session_opened")
        self.assertEqual(by_line[24].event_type, "session_closed")
        self.assertEqual(by_line[33].event_type, "login_failed")
        self.assertIsNone(by_line[33].src_ip)
