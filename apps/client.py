
import socket
import argparse
import time
import math


def send_request(host, port, message, timeout):

    start_time = time.perf_counter()

    try:
        with socket.create_connection(
            (host, port), timeout=timeout
        ) as client:

            client.settimeout(timeout)

            with client.makefile("r", encoding="utf-8") as reader:

                client.sendall(
                    (message + "\n").encode("utf-8")
                )

                response = reader.readline()

                if not response:
                    raise ConnectionError("Server closed connection")

                end_time = time.perf_counter()

                rtt = (end_time - start_time) * 1000

                expected = f"ACK: {message}"

                if response.rstrip("\r\n") != expected:
                    raise ValueError("Unexpected ACK received")

                return rtt, response.rstrip("\r\n")

    except (OSError, ValueError, ConnectionError) as error:
        print(f"[ERROR] {error}")
        return None, None


def main():

    parser = argparse.ArgumentParser(
        description="Dynamic Firewall TCP Client"
    )

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--message", default="Hello")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--count", type=int, default=1)

    args = parser.parse_args()

    if args.count < 1 or args.timeout <= 0:
        parser.error("Count and timeout must be positive")

    results = []

    print("\nDYNAMIC FIREWALL - TCP CLIENT")
    print("=" * 40)

    for i in range(args.count):

        rtt, response = send_request(
            args.host,
            args.port,
            args.message,
            args.timeout
        )

        if rtt is not None:

            results.append(rtt)

            print(
                f"Request {i + 1}: {response} | "
                f"RTT: {rtt:.3f} ms"
            )

        else:
            print(f"Request {i + 1}: FAILED")

    if results:

        sorted_results = sorted(results)

        mean_rtt = sum(results) / len(results)

        p95_index = math.ceil(0.95 * len(results)) - 1
        p95_rtt = sorted_results[p95_index]

        print("\n========== RTT SUMMARY ==========")
        print(f"Successful requests: {len(results)}/{args.count}")
        print(f"Mean RTT: {mean_rtt:.3f} ms")
        print(f"95th percentile RTT: {p95_rtt:.3f} ms")


if __name__ == "__main__":
    main()
