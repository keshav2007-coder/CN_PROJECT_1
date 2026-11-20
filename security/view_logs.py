
import sqlite3
import argparse
from pathlib import Path


DEFAULT_DB = Path(__file__).with_name("events.db")


def display_logs(db_path):

    if not Path(db_path).exists():
        print("No security event database found.")
        return

    with sqlite3.connect(db_path) as connection:

        cursor = connection.execute("""
            SELECT
                timestamp_utc,
                action,
                src_ip,
                reason,
                dst_ip,
                dst_port
            FROM security_events
            ORDER BY timestamp_utc DESC
        """)

        records = cursor.fetchall()

    print("\n" + "=" * 85)
    print("        DYNAMIC FIREWALL - SECURITY EVENT LOGS")
    print("=" * 85)

    if not records:
        print("No security events recorded.")
        return

    for record in records:

        timestamp, action, src_ip, reason, dst_ip, dst_port = record

        print(f"\nTimestamp : {timestamp}")
        print(f"Action    : {action}")
        print(f"Client IP : {src_ip}")
        print(f"Reason    : {reason}")
        print(f"Target IP : {dst_ip or 'N/A'}")
        print(f"Port      : {dst_port or 'N/A'}")

        print("-" * 85)

    print(f"\nTotal security events: {len(records)}")


def main():

    parser = argparse.ArgumentParser(
        description="View Dynamic Firewall Security Logs"
    )

    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB)
    )

    args = parser.parse_args()

    display_logs(args.db)


if __name__ == "__main__":
    main()
