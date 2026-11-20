
import socket
import argparse
import time


def generate_traffic(host, port, attempts, interval, timeout,
                     source_port_start):

    print("\nDYNAMIC FIREWALL - TRAFFIC GENERATOR")
    print("=" * 45)

    for i in range(attempts):

        source_port = source_port_start + i

        client = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        client.settimeout(timeout)

        try:
            client.bind(("", source_port))

            print(
                f"\nAttempt {i + 1}: "
                f"Source port {source_port}"
            )

            client.connect((host, port))

            print("[SUCCESS] Connection established")

        except socket.timeout:
            print("[TIMEOUT] Connection timed out")

        except ConnectionRefusedError:
            print("[REFUSED] Connection refused")

        except OSError as error:
            print(f"[ERROR] {error}")

        finally:
            client.close()

        if i < attempts - 1:
            time.sleep(interval)

    print("\nTraffic generation completed.")


def main():

    parser = argparse.ArgumentParser(
        description="Dynamic Firewall Traffic Generator"
    )

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--timeout", type=float, default=3)
    parser.add_argument("--source-port-start", type=int, default=45000)

    args = parser.parse_args()

    if args.attempts < 1:
        parser.error("Attempts must be at least 1")

    if args.interval < 0 or args.timeout <= 0:
        parser.error("Invalid interval or timeout")

    if not 1 <= args.source_port_start <= 65535:
        parser.error("Invalid source port")

    if args.source_port_start + args.attempts - 1 > 65535:
        parser.error("Source port range exceeds 65535")

    generate_traffic(
        args.host,
        args.port,
        args.attempts,
        args.interval,
        args.timeout,
        args.source_port_start
    )


if __name__ == "__main__":
    main()
