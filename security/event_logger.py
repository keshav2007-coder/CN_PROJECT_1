
import socketserver
import sqlite3
import json
import argparse

from pathlib import Path


DEFAULT_DB = Path(__file__).with_name("events.db")


def initialize_database(db_path):

    connection = sqlite3.connect(db_path)

    try:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                action TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT,
                dst_port INTEGER,
                reason TEXT NOT NULL,
                response_ms REAL,
                cookie TEXT
            )
        """)

        connection.commit()

    finally:
        connection.close()


def save_event(event, db_path):

    required = (
        "event_id",
        "timestamp_utc",
        "action",
        "src_ip",
        "reason"
    )

    if not isinstance(event, dict):
        raise ValueError("Event must be a JSON object")

    if any(not event.get(field) for field in required):
        raise ValueError("Missing required event fields")

    if event["action"] not in ("DENY", "BLOCK", "RECOVER"):
        raise ValueError("Invalid event action")

    if event.get("dst_port") is not None:

        port = event["dst_port"]

        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
        ):
            raise ValueError("Invalid destination port")

    connection = sqlite3.connect(db_path, timeout=5)

    try:

        cursor = connection.execute("""
            INSERT OR IGNORE INTO security_events
            (
                event_id,
                timestamp_utc,
                action,
                src_ip,
                dst_ip,
                dst_port,
                reason,
                response_ms,
                cookie
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event["event_id"],
            event["timestamp_utc"],
            event["action"],
            event["src_ip"],
            event.get("dst_ip"),
            event.get("dst_port"),
            event["reason"],
            event.get("response_ms"),
            str(event["cookie"])
            if event.get("cookie") is not None else None
        ))

        connection.commit()

        return cursor.rowcount == 1

    finally:
        connection.close()


class LoggerHandler(socketserver.StreamRequestHandler):

    def handle(self):

        client_ip = self.client_address[0]

        print(f"[LOGGER] Connected: {client_ip}")

        while True:

            line = self.rfile.readline(1024 * 1024)

            if not line:
                break

            try:

                event = json.loads(line.decode("utf-8"))

                inserted = save_event(
                    event,
                    self.server.db_path
                )

                acknowledgement = {
                    "status": "ok",
                    "event_id": event["event_id"],
                    "inserted": inserted
                }

                print(
                    f"[EVENT] {event['action']} | "
                    f"{event['src_ip']} | "
                    f"{event['reason']}"
                )

            except (ValueError, UnicodeDecodeError) as error:

                acknowledgement = {
                    "status": "error",
                    "message": str(error)
                }

            except (sqlite3.Error, KeyError) as error:

                acknowledgement = {
                    "status": "error",
                    "message": str(error)
                }

            response = json.dumps(acknowledgement) + "\n"

            self.wfile.write(response.encode("utf-8"))
            self.wfile.flush()

        print(f"[LOGGER] Disconnected: {client_ip}")


class LoggerServer(socketserver.ThreadingTCPServer):

    allow_reuse_address = True

    # Wait for handler threads during shutdown
    daemon_threads = False

    # Wait for all handler threads before closing server
    block_on_close = True


def main():

    parser = argparse.ArgumentParser(
        description="Dynamic Firewall Central Event Logger"
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=9000
    )

    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB)
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")

    db_path = Path(args.db).resolve()

    db_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    initialize_database(db_path)

    with LoggerServer(
        (args.host, args.port),
        LoggerHandler
    ) as server:

        server.db_path = str(db_path)

        print("=" * 45)
        print("DYNAMIC FIREWALL - EVENT LOGGER")
        print("=" * 45)

        print(f"Listening on {args.host}:{args.port}")
        print(f"Database: {db_path}")
        print("Waiting for security events...")

        try:

            server.serve_forever()

        except KeyboardInterrupt:

            print("\nLogger shutting down...")


if __name__ == "__main__":
    main()
