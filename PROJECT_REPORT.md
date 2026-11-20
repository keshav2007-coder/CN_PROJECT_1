# Dynamic Firewall with Security Event Logger

## Problem statement and objectives

A fixed firewall can reject an unauthorized connection but does not automatically restrict a source that repeatedly violates policy. This project combines a TCP application with an SDN firewall that detects repeated unauthorized attempts, temporarily blocks the source, restores access after expiry, and records security events centrally.

The objectives are to demonstrate socket communication between multiple clients, OpenFlow enforcement in Mininet, automatic blocking and recovery, persistent event logging, and a measured comparison with static filtering. The implementation and submitted measurements use the real policy and event sender.

## System architecture

```text
H1 client ─┐
H2 client ─┼─ S1 OpenFlow switch ─ H4 TCP application server
H3 client ─┘          │                 and iperf3 service
                     │ OpenFlow 1.3
              OS-Ken controller
                ├─ PolicyEngine
                └─ EventSender ─ TCP/JSON ─ Logger ─ SQLite
```

The controller and logger run in the Linux root network namespace. The application clients and server run inside Mininet hosts. Therefore, controller-to-logger communication uses `127.0.0.1:9000`, while clients explicitly target H4 at `10.0.0.10`. A Mininet host's loopback does not reach the root-namespace logger.

## Technologies and components

The recorded integration environment uses Ubuntu 26.04.1 LTS, Python 3.14.4, Mininet 2.3.0, Open vSwitch 3.7.1, OS-Ken 3.1.1, iperf3 3.20, and OpenFlow 1.3. Application, policy and logging modules use the Python standard library. The original guide's Python 3.10 baseline differs from the tested runtime.

| Component | Responsibility |
|---|---|
| `network/topology.py` | Creates four hosts and one switch connected to a remote controller |
| `firewall/controller.py` | Extracts connection metadata, installs flow rules, handles recovery and records barrier timing |
| `security/policy.py` | Classifies traffic and counts distinct unauthorized attempts |
| `apps/server.py`, `apps/client.py` | Concurrent TCP service and request/ACK clients |
| `apps/traffic.py` | Generates distinct unauthorized TCP connection attempts |
| `security/event_sender.py` | Queues and delivers security events over TCP |
| `security/event_logger.py`, `security/view_logs.py` | Store events in SQLite and retrieve them for inspection |
| `network/benchmark.py` | Captures individual RTTs, throughput trials and firewall-state evidence |

## Mininet topology

All hosts use a `/24` prefix and connect directly to S1.

| Host | IPv4 address | Switch port | Role |
|---|---|---|---|
| H1 | `10.0.0.1` | 1 | Authorized client |
| H2 | `10.0.0.2` | 2 | Authorized client and unauthorized-attempt source |
| H3 | `10.0.0.3` | 3 | Legitimate client used for performance measurements |
| H4 | `10.0.0.10` | 4 | Application server on TCP 5000; throughput service on TCP 5201 |

S1 uses OpenFlow 1.3 and connects to the controller at `127.0.0.1:6653`. TCP 5001 is the restricted destination port; no application listener is needed there to demonstrate filtering.

## TCP communication

The client opens a TCP connection, sends a UTF-8 message terminated by a newline, and expects `ACK: <message>` followed by a newline. It validates the ACK and treats connection errors, timeouts and unexpected replies as failed requests. Each client request opens a new connection. The server can handle multiple messages on an existing connection and uses `ThreadingTCPServer` to serve clients concurrently. Three concurrent clients were reported successful during live integration.

## Controller operation and traffic classification

The controller handles SwitchFeatures, PacketIn, FlowRemoved and BarrierReply events. Table-miss packets reach the controller. ARP and ICMP use the fixed topology's destination-port map. A new, unfragmented TCP SYN with ACK unset produces a traffic dictionary containing source/destination IP, source/destination port, protocol `TCP`, and flags `SYN`.

`PolicyEngine.evaluate()` returns an action and a reason. TCP connections to H4 ports 5000 and 5201 are allowed unless the source is blocked; other connections reaching evaluation are unauthorized. The controller enforces the decision with these priorities:

| Priority | Rule | Lifetime |
|---|---|---|
| 400 | Source IPv4 BLOCK with no forwarding actions | 30-second hard timeout; removal notification requested |
| 300 | Exact TCP five-tuple DENY | 10-second hard timeout |
| 200 | Forward and reverse approved TCP five-tuples | No timeout configured |
| 100 / 50 | ICMP / ARP forwarding | No timeout configured |
| 0 | Table miss to controller | No timeout configured |

The TCP five-tuple consists of source IP, destination IP, source port, destination port and protocol. An approved first SYN is forwarded immediately. A source block has higher priority than existing approved flows, so it also interrupts that source's previously allowed IPv4 traffic. ARP is outside this IPv4 block match.

## Automatic blocking and recovery

In dynamic mode, three distinct denied TCP SYN attempts from the same source within 10 seconds trigger BLOCK. Retransmissions with the same connection tuple count once within the window; different source ports distinguish new attempts. The real policy retains attempts exactly 10 seconds old and expires older attempts.

The controller assigns a unique cookie to the source drop rule and calls `mark_block_installed()`. The switch enforces the 30-second hard timeout. A matching FlowRemoved notification causes `mark_block_removed()` to clear policy history and permits a RECOVER event. A wrong cookie cannot clear the current block. Recovery depends on the switch notification, not a separate Python expiry timer.

Static mode uses the same permitted destinations and exact-connection DENY rules but never escalates violations to a source BLOCK. Changing an environment variable does not change a running controller. Controller and topology were restarted between modes to avoid stale policy state and flow rules.

## Centralized security-event logging

DENY, BLOCK and RECOVER events enter the sender's bounded background queue. The sender converts controller fields `event_type` and `timestamp` into `action` and `timestamp_utc`, assigns an event ID, and sends newline-delimited UTF-8 JSON. Events contain source IP and reason, with destination information and a cookie where applicable.

The threaded logger validates events, commits them to SQLite, and replies with JSON containing `status`, `event_id` and `inserted`. The sender confirms delivery only when status is `ok` and the event ID matches. SQLite uses `event_id` as the primary key and `INSERT OR IGNORE` for retry deduplication. Cookies are stored as text to support the full unsigned 64-bit range. The viewer retrieves timestamp, action, source, reason and destination fields.

## Testing methodology and evidence

Live integration was reported successful for controller connectivity, authorized application exchanges, three concurrent clients, denial, source blocking, recovery, TCP logging, acknowledgement and deduplication. The supplied policy suite contains ten tests for classification, threshold, duplicate attempts, expiry, static mode and cookie recovery. The logger suite tests event storage and duplicate IDs using its own temporary database and TCP listener; no tests or services were rerun to write this report.

The saved benchmark evidence was independently checked during documentation:

- Each condition has three trials, each with 30 successful H3 request/ACK measurements: 90 samples per condition, 270 overall.
- Every throughput trial lasts approximately 10 seconds. Three receiver-side Mbps measurements are retained per condition.
- RTT includes TCP establishment and application exchange, measured inside the client; interpreter startup is excluded. The mean and nearest-rank p95 use successful samples, aggregated across the three trials.
- H3 RTT and iperf run concurrently in every condition. Static and dynamic trials also generate three H2 attempts using one-second connect timeouts and one-second intervals, approximately two seconds between attempts when connections time out.
- All six saved unauthorized-attempt batches contain three timeouts. Static flow snapshots contain no H2 source block; all dynamic snapshots contain one; all recovery snapshots show it removed. H2 ACK checks agree with those states.
- A read-only inspection of an available temporary event database found DENY, BLOCK and RECOVER records. All three benchmark block cookies have matching BLOCK/RECOVER pairs. The database also includes earlier tests, so its total event count is not treated as a benchmark-only count. It is outside the retained project directory and should not be assumed to accompany these documents.

## Actual benchmark comparison

Values below are rounded from the saved CSV measurements. All three conditions have saved status PASS, 90/90 successful requests and 3/3 throughput trials.

| Condition | TCP RTT mean (ms) | TCP RTT p95 (ms) | Mean receiver throughput (Mbps) | H2 state |
|---|---:|---:|---:|---|
| Static with unauthorized attempts | 160.953 | 216.852 | 75,000.843 | Reachable; restricted attempts denied |
| Dynamic with unauthorized attempts | 164.938 | 216.005 | 76,628.331 | Source blocked |
| Dynamic after expiry | 184.603 | 215.631 | 72,708.855 | Reachable again |

Individual receiver throughput measurements are preserved as follows:

| Condition | Trial 1 (Mbps) | Trial 2 (Mbps) | Trial 3 (Mbps) |
|---|---:|---:|---:|
| Static | 76,481.259 | 76,665.595 | 71,855.676 |
| Dynamic | 77,667.823 | 76,459.719 | 75,757.450 |
| Recovered | 73,343.774 | 73,069.215 | 71,713.574 |

The dynamic BarrierReply response measurements were **0.982, 1.092 and 1.020 ms**, with a mean of **1.031 ms**. This timer starts in the controller's BLOCK branch and ends at the matching BarrierReply. It measures controller/switch rule-processing response; it excludes earlier policy evaluation and does not independently measure the first packet actually dropped. It is separate from TCP RTT and the 30-second block duration.

Evidence files:

- `benchmark-results.GHxubQ/comparison-0b5ee436.csv`
- `benchmark-results.GHxubQ/static-ea16e937ce/measurements.csv` and `summary.csv`
- `benchmark-results.GHxubQ/dynamic-03b1279ded/measurements.csv` and `summary.csv`
- `benchmark-results.GHxubQ/dynamic-response.csv`
- Per-trial `*-iperf.json`, `*-flows.txt`, `*-attack.txt` and application logs in the same benchmark directory.

## Observations and limitations

Legitimate H3 requests succeeded in all measured conditions while H2's access changed according to policy. Recovery restored H2 communication without a manual unblock. The data demonstrates functional isolation and a completed static comparison; three throughput trials do not establish a statistically significant performance improvement.

The very high throughput values describe local virtual networking without configured link bandwidth limits, not physical network capacity. RTT was measured during simultaneous iperf traffic, so it is not an unloaded latency baseline. The recovered condition was measured after the dynamic trials; ordering and runtime scheduling may affect comparisons.

The topology, permitted server and thresholds are fixed in code; no shared configuration loader is implemented. Enforcement evaluates new IPv4 TCP SYNs and does not provide general UDP, IPv6, payload inspection or authenticated identity checks. Approved flow rules have no configured expiry, so repeated use can grow the table. Disconnect/restart state reconciliation is outside the implemented demonstration.

Application and logger handlers lack idle-read timeouts. The sender has a 1,000-event queue, finite retries and no durable spool; queue acceptance alone does not prove storage. The controller does not explicitly drain the queue at shutdown. Central logging is plain TCP without authentication or encryption, appropriate to this controlled local demonstration. These are prototype limits rather than production-security claims.

## Conclusion

The project integrates TCP socket programming, concurrent clients, programmable OpenFlow filtering and centralized event storage. Saved measurements confirm all 270 legitimate benchmark requests succeeded, dynamic enforcement blocked the violating source, and expiry restored its access. The static, dynamic and recovery comparison provides reproducible local evidence while keeping application RTT, throughput and controller/switch response timing distinct.
