"""OpenFlow 1.3 enforcement for the fixed four-host project topology.

Run from the project root with PYTHONPATH=. and osken-manager.
FIREWALL_USE_MOCKS=1 explicitly selects temporary dependencies; otherwise
security.policy and security.event_sender must exist. FIREWALL_MODE selects
dynamic (default) or static. FIREWALL_RESPONSE_CSV defaults to
block_response.csv, created on the first matched block BarrierReply.

Provisional integration formats, pending teammate agreement:
traffic: dict(src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags).
events: dict(event_type, timestamp, src_ip, dst_ip, dst_port, reason), with
cookie added for BLOCK/RECOVER. Timestamps are UTC ISO 8601 strings.
CSV: timestamp,src_ip,cookie,response_ms. Timing ends at BarrierReply;
it measures controller/switch processing, not independent packet-drop proof.
"""

import csv
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import arp, ethernet, ether_types, icmp, ipv4, packet, tcp
from os_ken.ofproto import ofproto_v1_3

if os.environ.get("FIREWALL_USE_MOCKS") == "1":
    from firewall.mock_deps import PolicyEngine, EventSender
else:
    from security.policy import PolicyEngine
    from security.event_sender import EventSender


HOST_PORTS = {"10.0.0.1": 1, "10.0.0.2": 2, "10.0.0.3": 3, "10.0.0.10": 4}


class DynamicFirewall(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        mode = os.environ.get("FIREWALL_MODE", "dynamic")
        if mode not in ("dynamic", "static"):
            raise ValueError("FIREWALL_MODE must be dynamic or static")
        self.policy = PolicyEngine(mode=mode)
        self.sender = EventSender()
        self.blocks = {}
        self.pending_barriers = {}
        self.response_csv = Path(os.environ.get("FIREWALL_RESPONSE_CSV", "block_response.csv"))
        self.logger.info("Firewall mode=%s; dependencies=%s", mode,
                         "MOCK (terminal events only)" if os.environ.get("FIREWALL_USE_MOCKS") == "1" else "real")

    def add_flow(self, datapath, priority, match, actions, hard_timeout=0,
                 cookie=0, flags=0):
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=instructions, hard_timeout=hard_timeout,
            cookie=cookie, flags=flags))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        self.add_flow(datapath, 0, parser.OFPMatch(), [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)])

    def forward_packet(self, msg, output_port):
        datapath = msg.datapath
        parser, ofproto = datapath.ofproto_parser, datapath.ofproto
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=msg.match["in_port"],
            actions=[parser.OFPActionOutput(output_port)],
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None))

    def tcp_match(self, parser, traffic, reverse=False):
        source, destination = ("dst", "src") if reverse else ("src", "dst")
        return parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP, ip_proto=6,
            ipv4_src=traffic[source + "_ip"], ipv4_dst=traffic[destination + "_ip"],
            tcp_src=traffic[source + "_port"], tcp_dst=traffic[destination + "_port"])

    def emit_event(self, event_type, traffic, reason, cookie=None):
        event = {"event_type": event_type,
                 "timestamp": datetime.now(timezone.utc).isoformat(),
                 "src_ip": traffic["src_ip"], "dst_ip": traffic["dst_ip"],
                 "dst_port": traffic["dst_port"], "reason": reason}
        if cookie is not None:
            event["cookie"] = cookie
        try:
            self.sender.send_event(event)
        except Exception:
            self.logger.exception("Event sender failed for %s; delivery unconfirmed", event_type)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        frame = packet.Packet(msg.data)
        eth = frame.get_protocol(ethernet.ethernet)
        if eth is None or msg.msg_len < msg.total_len:
            return
        arp_packet = frame.get_protocol(arp.arp)
        if arp_packet is not None:
            output_port = HOST_PORTS.get(arp_packet.dst_ip)
            if output_port is not None and output_port != msg.match["in_port"]:
                self.add_flow(datapath, 50, parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=arp_packet.dst_ip),
                    [parser.OFPActionOutput(output_port)])
                self.forward_packet(msg, output_port)
            return

        ip_packet = frame.get_protocol(ipv4.ipv4)
        if ip_packet is None:
            return
        output_port = HOST_PORTS.get(ip_packet.dst)
        if output_port is None or output_port == msg.match["in_port"]:
            return
        # PacketIns queued before the switch applies BLOCK must not leak out.
        if (datapath.id, ip_packet.src) in self.blocks:
            return
        if frame.get_protocol(icmp.icmp) is not None:
            self.add_flow(datapath, 100, parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ip_proto=1, ipv4_dst=ip_packet.dst),
                [parser.OFPActionOutput(output_port)])
            self.forward_packet(msg, output_port)
            return

        segment = frame.get_protocol(tcp.tcp)
        if segment is None or ip_packet.offset or ip_packet.flags & 1:
            return
        if not segment.bits & tcp.TCP_SYN or segment.bits & tcp.TCP_ACK:
            return
        traffic = {"src_ip": ip_packet.src, "dst_ip": ip_packet.dst,
                   "src_port": segment.src_port, "dst_port": segment.dst_port,
                   "protocol": "TCP", "tcp_flags": "SYN"}
        try:
            decision = self.policy.evaluate(traffic)
            action, reason = decision["action"], decision["reason"]
        except Exception:
            self.logger.exception("Policy evaluation failed; packet dropped")
            return
        if action == "ALLOW":
            source_port = HOST_PORTS.get(ip_packet.src)
            if source_port is None:
                return
            self.add_flow(datapath, 200, self.tcp_match(parser, traffic),
                          [parser.OFPActionOutput(output_port)])
            self.add_flow(datapath, 200, self.tcp_match(parser, traffic, reverse=True),
                          [parser.OFPActionOutput(source_port)])
            self.forward_packet(msg, output_port)
        elif action == "DENY":
            self.add_flow(datapath, 300, self.tcp_match(parser, traffic), [], hard_timeout=10)
            self.emit_event("DENY", traffic, reason)
        elif action == "BLOCK":
            started = time.monotonic()
            cookie = secrets.randbits(64) or 1
            while any(record[0] == cookie for record in self.blocks.values()):
                cookie = secrets.randbits(64) or 1
            self.add_flow(datapath, 400, parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_packet.src), [],
                hard_timeout=30, cookie=cookie, flags=datapath.ofproto.OFPFF_SEND_FLOW_REM)
            self.blocks[(datapath.id, ip_packet.src)] = (cookie, traffic.copy())
            self.policy.mark_block_installed(ip_packet.src, cookie)
            barrier = parser.OFPBarrierRequest(datapath)
            datapath.set_xid(barrier)
            self.pending_barriers[(datapath.id, barrier.xid)] = (
                started, ip_packet.src, cookie)
            datapath.send_msg(barrier)
            self.emit_event("BLOCK", traffic, reason, cookie)
        else:
            self.logger.error("Unknown policy action %r; packet dropped", action)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        source = msg.match.get("ipv4_src")
        key = (msg.datapath.id, source)
        record = self.blocks.get(key)
        if msg.priority != 400 or record is None or record[0] != msg.cookie:
            return
        if self.policy.mark_block_removed(source, msg.cookie):
            del self.blocks[key]
            reason = ("Block expired" if msg.reason == msg.datapath.ofproto.OFPRR_HARD_TIMEOUT
                      else "Matching block rule removed")
            self.emit_event("RECOVER", record[1], reason, msg.cookie)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        msg = ev.msg
        pending = self.pending_barriers.pop((msg.datapath.id, msg.xid), None)
        if pending is None:
            return
        started, source, cookie = pending
        elapsed_ms = (time.monotonic() - started) * 1000
        try:
            with self.response_csv.open("a+", newline="", encoding="utf-8") as stream:
                stream.seek(0, 2)
                writer = csv.writer(stream)
                if stream.tell() == 0:
                    writer.writerow(["timestamp", "src_ip", "cookie", "response_ms"])
                writer.writerow([datetime.now(timezone.utc).isoformat(), source,
                                 cookie, f"{elapsed_ms:.3f}"])
        except OSError:
            self.logger.exception("Could not save block response measurement")

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_handler(self, ev):
        msg = ev.msg
        self.logger.error("OpenFlow error: type=%s code=%s xid=%s; check switch rules",
                          msg.type, msg.code, msg.xid)
