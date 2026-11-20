# Implementation Guide

This guide explains the implemented local system and how to demonstrate it using existing software. Run commands from the project root. Shell commands belong in Ubuntu terminals; commands labelled Mininet belong at `mininet>`. No automated whole-system demo launcher is implemented.

## Project structure

```text
apps/
  client.py              TCP requests, ACK validation and client RTT summary
  server.py              Threaded newline-based TCP application service
  traffic.py             Distinct unauthorized TCP connection attempts
firewall/
  controller.py          OpenFlow enforcement, recovery and BarrierReply timing
  mock_deps.py           Earlier development substitutes; not used in final runs
network/
  topology.py            Four hosts and one OpenFlow 1.3 switch
  benchmark.py           Mininet benchmark helper and comparison CSV export
security/
  __init__.py            Package initializer
  policy.py              Static/dynamic decisions and per-source violation state
  event_sender.py        Queued TCP/JSON delivery with acknowledgement/retries
  event_logger.py        Threaded receiver and SQLite storage
  view_logs.py           Display stored events
  test_policy.py         Ten isolated policy unit tests
  test_logger.py         Temporary-database TCP logging tests
benchmark-results.GHxubQ/
  comparison-0b5ee436.csv
  dynamic-response.csv
  static-ea16e937ce/      Static samples, summary and raw evidence
  dynamic-03b1279ded/     Dynamic/recovery samples, summary and raw evidence
block_response.csv       Earlier controller response measurements
PROJECT_COMPATIBILITY.md
PROJECT_REPORT.md
IMPLEMENTATION_GUIDE.md
DEMO_CHECKLIST.md
```

The original DOCX implementation guide and official PDF rubric are not included in this snapshot. There is no `config/project.json` or shared JSON configuration loader in the current implementation. Runtime mode and response-output path use environment variables; network and policy constants remain in source. Existing measurement files must be retained.

## Prerequisites and recorded versions

| Component | Recorded integration version |
|---|---|
| Ubuntu | 26.04.1 LTS |
| Python | 3.14.4 |
| Mininet | 2.3.0 |
| Open vSwitch | 3.7.1 |
| OS-Ken | 3.1.1, in `.venv` |
| iperf3 | 3.20 |
| OpenFlow | 1.3 |

Create the controller virtual environment using `README.md` first. Use system Python for Mininet and the new virtual environment's `osken-manager` for the controller. Mininet requires administrator authorization; the logger and controller do not. SQLite support comes from Python's standard library. The original virtual environment is excluded; a fresh checkout requires the setup in `README.md`.

These versions are recorded in `PROJECT_COMPATIBILITY.md`. Its early statement that live integration was untested predates the subsequently completed live tests and saved benchmarks. It has been preserved unchanged.

## Startup order

Use logger → controller → Mininet → H4 application server. Start from a clean project test session; do not stop unrelated processes or remove unrelated switches.

### Terminal 1: logger in the root network namespace

Check both root-namespace service ports. A listener row means the port is occupied; identify it before proceeding.

```bash
ss -ltnp '( sport = :9000 or sport = :6653 )'
export RUN_DIR="$(mktemp -d demo-output.XXXXXX)"
printf 'Run directory: %s\n' "$RUN_DIR"
python3 -B -u security/event_logger.py \
  --host 127.0.0.1 --port 9000 --db "$RUN_DIR/events.db"
```

The unique directory protects existing databases and CSVs. Copy the printed relative directory name into the other terminals when prompted.

### Terminal 2: real dynamic controller

```bash
read -r -p "Run directory: " RUN_DIR
test -d "$RUN_DIR" || exit 1
env -u FIREWALL_USE_MOCKS \
  FIREWALL_MODE=dynamic \
  FIREWALL_RESPONSE_CSV="$PWD/$RUN_DIR/block-response.csv" \
  PYTHONPATH="$PWD" PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/osken-manager \
  --ofp-listen-host 127.0.0.1 --ofp-tcp-listen-port 6653 \
  firewall/controller.py
```

Confirm `mode=dynamic; dependencies=real`. `FIREWALL_USE_MOCKS=1` selects development substitutes and must not be used for the final demonstration.

### Terminal 3: existing Mininet topology

```bash
read -r -p "Run directory: " RUN_DIR
test -d "$RUN_DIR" || exit 1
sudo env RUN_DIR="$PWD/$RUN_DIR" PYTHONPATH="$PWD" \
  PYTHONDONTWRITEBYTECODE=1 python3 -B network/topology.py
```

In Mininet, confirm connectivity and check H4's application port:

```text
nodes
net
sh ovs-vsctl get Controller s1 is_connected
h4 ss -ltnp 'sport = :5000'
```

Expect `true` for the switch connection and no listener on H4:5000 before startup. Then start the existing application, retaining its process handle for cleanup:

```text
px import os, subprocess
px app = net.get('h4').popen(['python3', '-B', '-u', 'apps/server.py', '--host', '0.0.0.0', '--port', '5000'], stdout=open(os.path.join(os.environ['RUN_DIR'], 'app.log'), 'x'), stderr=subprocess.STDOUT)
h4 ss -ltnp 'sport = :5000'
```

Relative application paths work because the topology is launched from the project root. The `RUN_DIR` environment variable is passed explicitly through sudo.

## Application and SDN communication

H1, H2 and H3 connect through S1 to H4 at `10.0.0.10:5000`. Requests and `ACK: <message>` responses are UTF-8 lines. The server creates handler threads for concurrent clients. For example, in Mininet:

```text
h3 python3 -B apps/client.py --host 10.0.0.10 --port 5000 --message Hello --timeout 2
```

Client options are `--host`, `--port`, `--message`, `--timeout` and `--count`. Server options are `--host` and `--port`. Always supply H4's address: the client default is loopback within its own namespace.

The switch sends unmatched packets to the controller. The controller calls the policy for new TCP SYNs, installs exact forward/reverse ALLOW rules or exact DENY rules, and forwards the first approved packet. Dynamic escalation installs a higher-priority source IPv4 drop. FlowRemoved and cookie matching synchronize recovery; BarrierReply completes the separate response timer.

## Policy modes and event delivery

Static mode denies unauthorized connections without source blocking. Dynamic mode blocks a source after three distinct violations in 10 seconds and restores access after the switch's 30-second rule expires. Start the controller with the desired `FIREWALL_MODE`. To change modes safely, stop the application and topology, stop the controller, then restart controller, topology and application. Changing a variable cannot reconfigure a running controller. The logger can remain running.

Events travel from the controller's background sender to the root-namespace logger at `127.0.0.1:9000`. JSON messages and ACKs are newline-delimited. The logger commits SQLite records before acknowledgement; repeated IDs are ignored rather than inserted twice. Do not attempt to reach this loopback service from a Mininet host.

To view the current demonstration's events in Terminal 1 after stopping the logger, or in another root-namespace terminal with the same `RUN_DIR`:

```bash
python3 -B security/view_logs.py --db "$RUN_DIR/events.db"
```

The default database is `security/events.db`, but it is not present in this project snapshot. A temporary integration database was inspected for the report; its availability is not guaranteed after cleanup or transfer. Use the explicit database path for each new demonstration.

## View existing benchmark evidence

No new measurements are needed to present the completed comparison:

```bash
cat benchmark-results.GHxubQ/comparison-0b5ee436.csv
cat benchmark-results.GHxubQ/static-ea16e937ce/summary.csv
cat benchmark-results.GHxubQ/dynamic-03b1279ded/summary.csv
cat benchmark-results.GHxubQ/dynamic-response.csv
```

Individual values are in each run's `measurements.csv`; raw iperf JSON, attack output and flow snapshots are adjacent. `PROJECT_REPORT.md` presents the measured comparison with interpretation and limitations.

The existing benchmark API is `bench.run(net, mode, output_root, response_csv)` from Mininet after `import network.benchmark as bench`. Dynamic runs also measure recovery. It creates unique output directories, captures child-process output directly and cleans up its own iperf server. It does not start the application or change controller mode. Its `--summarize OUTPUT_ROOT` option generates an additional comparison CSV, so use the saved comparison above for read-only viewing. Benchmarking need not be repeated during the teacher demonstration.

## Safe shutdown

Allow RECOVER delivery to finish and verify the database record before stopping services. In Mininet, stop the application started with the retained handle, then exit:

```text
py app.send_signal(2)
py app.wait(timeout=5)
exit
```

Skip handle commands if that application was not started. Topology cleanup runs in `finally`. Stop the controller with Ctrl+C, then stop the logger with Ctrl+C. Verify ports 6653 and 9000 no longer have this session's listeners. Keep the run directory as evidence; do not remove existing benchmark results or databases. Avoid broad process-kill or global network-cleanup commands.
