"""Temporary policy and terminal event sink; no centralized logger delivery.

Development traffic is a dict with the six fields named in the project guide.
Distinct attempts use the TCP 5-tuple; retransmissions count once per window.
The switch's matching FlowRemoved event, not a Python timer, ends a block.
"""

import json
import time


class PolicyEngine:
    def __init__(self, mode="dynamic"):
        if mode not in ("dynamic", "static"):
            raise ValueError("mode must be dynamic or static")
        self.mode = mode
        self.attempts = {}
        self.blocks = {}

    def evaluate(self, traffic):
        source = traffic["src_ip"]
        if source in self.blocks:
            return {"action": "BLOCK", "reason": "Source block is active"}
        if traffic["dst_port"] in (5000, 5201):
            return {"action": "ALLOW", "reason": "Approved TCP destination port"}
        if self.mode == "static":
            return {"action": "DENY", "reason": "Unauthorized TCP destination port"}

        now = time.monotonic()
        attempts = self.attempts.setdefault(source, {})
        for key, timestamp in list(attempts.items()):
            if now - timestamp >= 10:
                del attempts[key]
        key = tuple(traffic[field] for field in (
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol"
        ))
        attempts.setdefault(key, now)
        if len(attempts) >= 3:
            return {"action": "BLOCK", "reason": "Three distinct denied SYN attempts within 10 seconds"}
        return {"action": "DENY", "reason": "Unauthorized TCP destination port"}

    def mark_block_installed(self, src_ip, cookie):
        self.blocks[src_ip] = cookie

    def mark_block_removed(self, src_ip, cookie):
        if self.blocks.get(src_ip) != cookie:
            return False
        del self.blocks[src_ip]
        self.attempts.pop(src_ip, None)
        return True


class EventSender:
    def send_event(self, event):
        print("MOCK EVENT (terminal only): " + json.dumps(event, sort_keys=True), flush=True)
