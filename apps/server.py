
import socketserver
import argparse


class TCPHandler(socketserver.StreamRequestHandler):

    def handle(self):
        client_ip = self.client_address[0]

        print(f"[CONNECTED] Client: {client_ip}")

        while True:
            message = self.rfile.readline(65536)

            if not message:
                break

            try:
                text = message.decode("utf-8").rstrip("\r\n")

                print(f"[RECEIVED] {client_ip}: {text}")

                response = f"ACK: {text}\n"
                self.wfile.write(response.encode("utf-8"))
                self.wfile.flush()

                print(f"[ACK SENT] {client_ip}")

            except UnicodeDecodeError:
                print(f"[ERROR] Invalid UTF-8 from {client_ip}")
                break

        print(f"[DISCONNECTED] Client: {client_ip}")


class TCPServer(socketserver.ThreadingTCPServer):

    allow_reuse_address = True
    daemon_threads = True


def main():

    parser = argparse.ArgumentParser(
        description="Dynamic Firewall TCP Application Server"
    )

    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)

    args = parser.parse_args()

    with TCPServer((args.host, args.port), TCPHandler) as server:

        print("=" * 45)
        print("DYNAMIC FIREWALL - TCP SERVER")
        print("=" * 45)
        print(f"Server running on {args.host}:{args.port}")
        print("Waiting for client connections...")
        print("Press Ctrl+C to stop the server.")

        try:
            server.serve_forever()

        except KeyboardInterrupt:
            print("\nServer shutting down...")


if __name__ == "__main__":
    main()
