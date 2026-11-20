# Project Compatibility and Integration

Dynamic Firewall with Security Event Logger — shared contract for the Linux SDN developer and Windows application, policy and logger developer.

> Historical integration contract: statements about untested integration and pending interfaces below predate the completed implementation. Use `README.md`, `IMPLEMENTATION_GUIDE.md` and `PROJECT_REPORT.md` for current setup and implemented behavior. No `config/project.json` is shipped or loaded.

## 1. Verified Linux software

| Required component | Verified version or protocol | Use |
|---|---|---|
| Ubuntu | 26.04.1 LTS | Final integration environment |
| Python | 3.14.4 | System Python and project virtual environment |
| Mininet | 2.3.0 | Four virtual hosts and one switch |
| Open vSwitch | 3.7.1 | OpenFlow switch |
| OS-Ken | 3.1.1 | Controller, installed in `.venv` |
| iperf3 | 3.20 | Throughput measurements |
| OpenFlow | 1.3 (`OpenFlow13`) | Required controller–switch protocol |

Mininet imports and OpenFlow 1.3 imports passed. Open vSwitch's switch and database services were running at verification. OS-Ken's launcher works and a brief controller test listened on TCP 6653. Eventlet reported an RLock warning, and interrupted shutdown produced a traceback. Actual Mininet–controller communication remains untested; full Python 3.14 runtime compatibility is not yet established.

The implementation guide targets Python 3.10 and Ubuntu 22.04; the table records the actual verified environment. Keep OS-Ken pinned to 3.1.1, as required by the guide, and use `osken-manager`. Run Mininet with system Python and the controller with `.venv` Python.

## 2. Platform responsibilities and portability

| Scope | Required software or libraries |
|---|---|
| Linux integration | Ubuntu/Linux, Python, Mininet, Open vSwitch, OS-Ken and iperf3 |
| Windows development | Python for the TCP application, policy engine and logger; no exact Windows Python version has been verified or mandated |
| Shared Python modules | Prefer the Python standard library; the guide specifies no shared third-party Python dependency |

The Windows developer does **not** need Mininet, Open vSwitch or OS-Ken. Windows supports independent application, policy and logger development; the complete SDN demonstration runs on Linux.

Use Python 3.10-compatible syntax and standard-library APIs where practical, reflecting the guide's baseline. Python 3.14 is not required on Windows. Test the delivered modules on Linux Python 3.14 before final integration. Use portable paths, explicit text encodings, socket timeouts and clear error handling. Avoid Windows-only imports, absolute local paths and OS-Ken imports in shared modules. Any new third-party dependency requires agreement and must work in each runtime that imports it; keep controller dependencies inside `.venv` and do not modify system Python packages.

## 3. Frozen network and policy settings

| Virtual host | IPv4 address | S1 port |
|---|---|---|
| H1 | `10.0.0.1/24` | 1 |
| H2 | `10.0.0.2/24` | 2 |
| H3 | `10.0.0.3/24` | 3 |
| H4 | `10.0.0.10/24` | 4 |

| Setting | Agreed value |
|---|---|
| Topology | One switch S1, four hosts; no extra routers or switches |
| Switch protocol | OpenFlow 1.3; Mininet setting `OpenFlow13` |
| Remote controller | `127.0.0.1:6653`, TCP |
| Application | H4, TCP port `5000`, ALLOW |
| Restricted destination port | TCP `5001`, DENY |
| Throughput service | H4, TCP `5201`, ALLOW |
| Central logger | `127.0.0.1:9000`, TCP |
| Dynamic threshold | 3 distinct denied TCP SYN attempts within 10 seconds |
| Dynamic block | Source IPv4 DROP for 30 seconds |
| Static mode | Deny restricted attempts without escalation to a source block |
| Shared configuration file | `config/project.json`; exact JSON schema still requires agreement |

Loopback refers to the local machine/network namespace. For final integration, the controller, policy and logger run on the Linux machine; the logger is not a remote Windows service. The application server runs inside H4. Do not assume that a Mininet host's loopback reaches the Linux root-namespace logger.

## 4. Python interfaces

These are the exact import paths and call forms specified by the guide; it does not provide full typed function definitions or additional return contracts.

```python
from security.policy import PolicyEngine
from security.event_sender import EventSender

policy = PolicyEngine(mode="dynamic")  # or "static"
decision = policy.evaluate(traffic)  # {'action': 'ALLOW|DENY|BLOCK', 'reason': str}
policy.mark_block_installed(src_ip, cookie)
policy.mark_block_removed(src_ip, cookie)  # True only for matching cookie
EventSender().send_event(event)  # non-blocking queued TCP event
```

`action` is one of `ALLOW`, `DENY`, or `BLOCK`; `reason` is a string. The pipe-separated expression above denotes alternatives, not one literal action value.

For a new TCP SYN with ACK=0, the controller supplies these traffic fields:

| Field | Guide requirement |
|---|---|
| `src_ip`, `dst_ip` | Source and destination IPv4 |
| `src_port`, `dst_port` | Source and destination TCP ports |
| `protocol` | `"TCP"` |
| `tcp_flags` | `"SYN"` |

The guide names these fields but does not explicitly define the `traffic` container type or full value types. Agree on that representation before implementing the shared API.

The controller calls the policy directly in its process. It installs OpenFlow rules and informs the policy when a block is installed or its matching rule is removed. A unique cookie identifies each block. Emit `RECOVER` only for matching block removal. `EventSender.send_event(event)` queues TCP delivery to the logger without blocking controller processing; the event payload and wire format are not specified.

### Rule behavior required for integration

| Priority | Rule | Lifetime |
|---|---|---|
| 400 | IPv4 source-IP BLOCK, overriding existing ALLOW rules | `hard_timeout=30`; unique cookie and FlowRemoved notification |
| 300 | Exact IPv4 TCP 5-tuple DENY | `hard_timeout=10` |
| 200 | Approved forward and reverse TCP 5-tuple output rules | Not specified |
| 100 / 50 | ICMP / ARP forwarding | Not specified |
| 0 | Table miss sends packets to controller | Not specified |

A 5-tuple comprises source/destination IP, source/destination port and protocol. Different new source ports must reach policy evaluation so distinct denied attempts are counted. Forward the first approved SYN; do not install a blanket TCP ALLOW. Handle SwitchFeatures, PacketIn, FlowRemoved and BarrierReply. Measure block response from the third denied SYN through the corresponding BarrierReply using a monotonic timer. Send DENY, BLOCK and RECOVER events to the logger.

### Items requiring developer agreement

- Exact `traffic` container/value types, distinct-attempt counting and time-window boundary behavior.
- Event fields, timestamps, serialization, TCP message framing, logger acknowledgement/retry behavior and sender queue lifecycle.
- Application request/ACK encoding and framing, client/traffic-generator command-line options and timeout behavior. The guide requires request/ACK exchanges but defines no wire format.
- Remaining method return/error behavior, policy concurrency assumptions, configuration JSON schema and measurement CSV columns.

Do not treat an unspecified detail as an established interface.

## 5. File ownership and handoff

| Owner | Project-relative files |
|---|---|
| Linux developer | `network/topology.py`, `network/benchmark.py`, `firewall/controller.py` |
| Linux developer, temporary testing | `firewall/mock_deps.py` |
| Windows developer | `apps/server.py`, `apps/client.py`, `apps/traffic.py` |
| Windows developer | `security/policy.py`, `security/event_logger.py`, `security/event_sender.py`, `security/view_logs.py` |
| Shared agreement | `config/project.json` |

The Windows developer delivers one ZIP containing portable `apps/` and `security/` Python packages. Extract them beside `network/` and `firewall/`, preserving filenames and import paths. Include the agreed protocol/API details, dependency requirements, launch instructions and tests needed to reproduce behavior. Do not include a Windows virtual environment or machine-specific configuration.

The server must support the guide's launch interface:

```text
python3 -u apps/server.py --host 0.0.0.0 --port 5000
```

That command runs inside H4. The logger entry point is `python3 security/event_logger.py`, run from the project root in the Linux root namespace. The final controller imports the real policy and sender, replacing temporary mocks. Start components in this order: logger, controller, Mininet, H4 application server, then clients and test traffic.

## 6. Integration acceptance

- H1, H2 and H3 receive application ACKs from H4:5000; multiple clients are supported.
- H2 makes three new connections to H4:5001, two seconds apart. Dynamic mode blocks H2's source IPv4 for 30 seconds; H2:5000 fails during the block while H3 remains functional. H2 reconnects after expiry, and DENY/BLOCK/RECOVER events are recorded.
- Compare static and dynamic modes using the same denied attempts. Measure legitimate H3 traffic during enforcement: 30 request/ACK RTT samples with mean/p95, and three 10-second iperf3 runs per condition. Record block response and recovery evidence in addition to throughput results.
- Deliver reproducible source, configuration, tests, measurements and documentation. The official rubric requires the final demo code in a GitHub repository. The ZIP is the integration handoff, not the final submission format.

This contract is based on the supplied Linux implementation guide and official evaluation rubric. Network values above are deliberately assigned project addresses; no personal machine or network identifiers are needed for integration.
