from pathlib import Path
import unittest

from loglab.parsers.app import parse_app


class AppTests(unittest.TestCase):
    def test_lab_stack(self):
        path = Path(__file__).resolve().parents[1] / "logs" / "app_error.log"
        lines = path.read_text().splitlines(keepends=True)
        events = list(parse_app(lines, file=str(path)))
        error = next(e for e in events if e.line_start == 9)
        self.assertEqual(error.line_end, 43)
        self.assertIn(44, [e.line_start for e in events])
        self.assertEqual(error.raw_message, "".join(lines[8:43]))
        self.assertEqual((error.timestamp, error.raw_timestamp), (None, "2025-12-30 10:07:30,112"))
        self.assertEqual(error.details["exception"], "java.lang.NullPointerException")
        self.assertEqual((error.details["level"], error.details["component"], error.details["thread"]),
                         ("ERROR", "com.example.app.service.ApiService", "Thread-12"))
        self.assertTrue(error.details["message"].startswith("Critical error"))

    def test_end_of_file(self):
        lines = ["2025-12-30 12:00:00,123 WARN [main] App: problem\r\n",
                 "java.io.IOException: failed\r\n", "\tat App.run(App.java:1)"]
        event, = parse_app(lines, file="sample")
        self.assertEqual((event.line_start, event.line_end, event.raw_message), (1, 3, "".join(lines)))
        self.assertEqual(event.details["exception"], "java.io.IOException")

    def test_invalid_and_orphan(self):
        lines = ["2025-12-30 12:00:00,123 INFO [main] App: ok\n", "broken\n",
                 "\tat App.run(App.java:1)\n", "2025-02-30 12:00:00,123 INFO [main] App: bad"]
        first, *errors = parse_app(lines, file="sample")
        self.assertEqual(first.line_end, 1)
        self.assertEqual([e.raw_message for e in errors], lines[1:])
        for event in errors:
            self.assertEqual(event.event_type, "app_invalid")
            self.assertIn("reason", event.details)
