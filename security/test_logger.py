
import unittest
import sqlite3
import tempfile
import threading

from pathlib import Path

from security.event_logger import (
    LoggerServer,
    LoggerHandler,
    initialize_database
)

from security.event_sender import EventSender


class TestEventLogger(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        # Create temporary database folder
        cls.temp_dir = tempfile.TemporaryDirectory()

        cls.db_path = str(
            Path(cls.temp_dir.name) / "events.db"
        )

        initialize_database(cls.db_path)

        # Start logger on an automatically assigned port
        cls.server = LoggerServer(
            ("127.0.0.1", 0),
            LoggerHandler
        )

        cls.server.db_path = cls.db_path

        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True
        )

        cls.server_thread.start()

        host, port = cls.server.server_address

        # Connect event sender to logger
        cls.sender = EventSender(
            host=host,
            port=port,
            timeout=1,
            max_retries=2
        )

    def setUp(self):

        # Clear database before every test
        connection = sqlite3.connect(self.db_path)

        try:

            connection.execute(
                "DELETE FROM security_events"
            )

            connection.commit()

        finally:

            connection.close()

    @classmethod
    def tearDownClass(cls):

        # Finish all pending events
        cls.sender.flush()

        # Stop event sender worker
        cls.sender.close()

        # Stop logger server
        cls.server.shutdown()

        # Wait for active client handler threads
        cls.server.server_close()

        # Wait for server thread
        cls.server_thread.join(timeout=5)

        if cls.server_thread.is_alive():
            raise RuntimeError("Logger server thread did not stop")

        # Delete temporary database after all connections close
        cls.temp_dir.cleanup()

    def make_event(self, event_id, action):

        return {
            "event_id": event_id,
            "timestamp_utc": "2026-11-11T10:00:00Z",
            "action": action,
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.10",
            "dst_port": 5001,
            "reason": "Test security event"
        }

    def get_event_count(self):

        connection = sqlite3.connect(self.db_path)

        try:

            result = connection.execute("""
                SELECT COUNT(*)
                FROM security_events
            """).fetchone()

            return result[0]

        finally:

            connection.close()

    def test_deny_event(self):

        event = self.make_event(
            "evt-001",
            "DENY"
        )

        self.assertTrue(
            self.sender.send_event(event)
        )

        self.sender.flush()

        self.assertEqual(
            self.get_event_count(),
            1
        )

    def test_block_event(self):

        event = self.make_event(
            "evt-002",
            "BLOCK"
        )

        self.assertTrue(
            self.sender.send_event(event)
        )

        self.sender.flush()

        self.assertEqual(
            self.get_event_count(),
            1
        )

    def test_recover_event(self):

        event = self.make_event(
            "evt-003",
            "RECOVER"
        )

        self.assertTrue(
            self.sender.send_event(event)
        )

        self.sender.flush()

        self.assertEqual(
            self.get_event_count(),
            1
        )

    def test_duplicate_event_id(self):

        event = self.make_event(
            "evt-004",
            "DENY"
        )

        self.assertTrue(
            self.sender.send_event(event)
        )

        self.sender.flush()

        self.assertTrue(
            self.sender.send_event(event)
        )

        self.sender.flush()

        # Duplicate event ID must not create another record
        self.assertEqual(
            self.get_event_count(),
            1
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
