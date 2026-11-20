
import time
import threading
from collections import defaultdict, deque


class PolicyEngine:

    def __init__(self, mode="dynamic", clock=time.monotonic):

        if mode not in ("static", "dynamic"):
            raise ValueError("Mode must be 'static' or 'dynamic'")

        self.mode = mode
        self.clock = clock

        # Firewall configuration
        self.server_ip = "10.0.0.10"
        self.allowed_ports = {5000, 5201}

        self.violation_limit = 3
        self.time_window = 10.0

        # Store denied attempts for each source IP
        self.violations = defaultdict(deque)

        # Store pending and installed blocks
        self.pending_blocks = set()
        self.active_blocks = {}

        # Protect shared state
        self.lock = threading.RLock()

    def _make_attempt_key(self, traffic):

        return (
            traffic["src_ip"],
            traffic["src_port"],
            traffic["dst_ip"],
            traffic["dst_port"]
        )

    def _remove_expired_attempts(self, src_ip, current_time):

        attempts = self.violations[src_ip]

        # Keep attempts within the 10-second window
        while attempts and current_time - attempts[0][0] > self.time_window:
            attempts.popleft()

    def evaluate(self, traffic):

        required_fields = (
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "tcp_flags"
        )

        # Validate incoming traffic information
        if not isinstance(traffic, dict):
            raise TypeError("Traffic must be a dictionary")

        if any(field not in traffic for field in required_fields):
            raise ValueError("Missing required traffic fields")

        src_ip = traffic["src_ip"]
        dst_ip = traffic["dst_ip"]
        dst_port = traffic["dst_port"]

        if not isinstance(src_ip, str) or not src_ip:
            raise ValueError("Invalid source IP")

        if not isinstance(dst_ip, str) or not dst_ip:
            raise ValueError("Invalid destination IP")

        if not isinstance(dst_port, int) or isinstance(dst_port, bool):
            raise ValueError("Invalid destination port")

        with self.lock:

            # Do not allow a pending or actively blocked source
            # to trigger a new block period.
            if (
                src_ip in self.pending_blocks
                or src_ip in self.active_blocks
            ):
                return {
                    "action": "BLOCK",
                    "reason": "Source IP is already pending or blocked"
                }

            # Only the agreed application server and ports
            # are authorized.
            if (
                dst_ip == self.server_ip
                and dst_port in self.allowed_ports
            ):
                return {
                    "action": "ALLOW",
                    "reason": "Authorized destination and port"
                }

            # Unauthorized traffic
            if self.mode == "static":
                return {
                    "action": "DENY",
                    "reason": "Unauthorized traffic in static mode"
                }

            # Dynamic mode: count distinct denied TCP SYN attempts
            if (
                str(traffic["protocol"]).upper() != "TCP"
                or str(traffic["tcp_flags"]).upper() != "SYN"
            ):
                return {
                    "action": "DENY",
                    "reason": "Unauthorized traffic"
                }

            current_time = self.clock()

            self._remove_expired_attempts(src_ip, current_time)

            attempt_key = self._make_attempt_key(traffic)

            attempts = self.violations[src_ip]

            # Ignore retransmitted SYN attempts
            if any(key == attempt_key for _, key in attempts):
                return {
                    "action": "DENY",
                    "reason": "Duplicate connection attempt ignored"
                }

            # Record the new distinct violation
            attempts.append((current_time, attempt_key))

            count = len(attempts)

            # Third distinct violation triggers a block
            if count >= self.violation_limit:

                self.pending_blocks.add(src_ip)

                return {
                    "action": "BLOCK",
                    "reason": "3 distinct unauthorized attempts within 10 seconds"
                }

            return {
                "action": "DENY",
                "reason": (
                    f"Unauthorized connection attempt "
                    f"({count}/{self.violation_limit})"
                )
            }

    def mark_block_installed(self, src_ip, cookie):

        with self.lock:

            # Associate the switch's block rule with its cookie
            self.active_blocks[src_ip] = cookie

            self.pending_blocks.discard(src_ip)

    def mark_block_removed(self, src_ip, cookie):

        with self.lock:

            # Only remove the block if the cookie matches
            if self.active_blocks.get(src_ip) != cookie:
                return False

            del self.active_blocks[src_ip]

            # Clear old violation history after recovery
            self.violations.pop(src_ip, None)

            self.pending_blocks.discard(src_ip)

            return True
