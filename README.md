# Dynamic Firewall with Security Event Logger

A Computer Networks mini-project combining a concurrent TCP application, an
OS-Ken OpenFlow 1.3 controller, automatic temporary source blocking, and a
central SQLite security-event logger.

## Architecture

```text
H1 (10.0.0.1) --+
H2 (10.0.0.2) --+-- S1 -- H4 (10.0.0.10): TCP 5000 / iperf3 5201
H3 (10.0.0.3) --+    |
                 OS-Ken controller -- TCP/JSON --> logger --> SQLite
```

The controller and logger run in the Linux root network namespace. The switch
connects to `127.0.0.1:6653`; controller events go to `127.0.0.1:9000`.
TCP 5000 and 5201 on H4 are approved. Three distinct unauthorized TCP SYN
attempts within 10 seconds trigger a 30-second source IPv4 block in dynamic
mode. Static mode denies unauthorized connections without escalation.
Matching OpenFlow removal notifications restore access and generate RECOVER.

## Prerequisites and setup

Run the full demonstration on a compatible Linux host with Mininet, Open
vSwitch, iperf3, system Python and Python virtual-environment support.
The recorded integration versions are in `PROJECT_REPORT.md`; they describe
the original experiment, not a guarantee for every distribution or runtime.
Python 3.10 was the original guide baseline; the recorded run used 3.14.4.
Application, policy, logger and tests use only the Python standard library.
OS-Ken 3.1.1 is the controller's direct Python dependency. Mininet is a Linux
system package and must be importable with system Python.

On an Ubuntu/Debian environment with these packages available:

```bash
sudo apt update
sudo apt install python3 python3-venv mininet openvswitch-switch iperf3 iproute2
sudo systemctl start openvswitch-switch
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
python3 -B -c 'import mininet.net'
.venv/bin/python -B -c 'import os_ken.base.app_manager'
```

Run all commands from the extracted project root. Do not activate the controller
virtual environment for the system-Python Mininet commands. Only Mininet needs
administrator privileges. Dependency installation was not repeated as part of
packaging; use a compatible distribution/package combination and inspect errors
before proceeding. The virtual environment is intentionally not distributed.

## Run the project

Follow [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for complete commands
and safe shutdown. Start these components in order, in separate terminals:

1. Logger bound to loopback, writing to a new `demo-output.*` database.
2. `.venv/bin/osken-manager` with `PYTHONPATH` set to the project directory,
   `FIREWALL_MODE=dynamic`, and an explicit fresh `FIREWALL_RESPONSE_CSV` path.
3. `sudo` system Python running `network/topology.py`.
4. The application server inside H4, followed by clients inside H1/H2/H3.

Keep `FIREWALL_USE_MOCKS` unset for real integration. To compare static mode,
restart both controller and topology with `FIREWALL_MODE=static`.
[DEMO_CHECKLIST.md](DEMO_CHECKLIST.md) covers authorization, denial, blocking,
unaffected H3 traffic, recovery and event inspection. Avoid using the default
`block_response.csv` for new runs: it contains retained historical measurements.

## Lightweight tests

```bash
python3 -B -m unittest security.test_policy security.test_logger -v
```

The logger tests bind an ephemeral loopback TCP port and use a temporary database.
They do not require Mininet or root privileges. These tests verify policy and
logging, not switch integration. A separate application smoke test can run the
server on loopback and use `apps/client.py` to check an ACK.

## Benchmarks and documentation

All supplied benchmark evidence is retained under `benchmark-results.GHxubQ/`,
including raw iperf results, attack output, flow snapshots, logs and comparisons.
The six comparison CSVs contain identical results and are preserved as supplied.
Each condition has 90 successful RTT samples and three throughput measurements.
The saved dynamic BarrierReply response mean is approximately 1.031 ms.
Machine hostnames and original home-directory paths have been sanitized; numerical
measurements are unchanged. Settings paths are project-relative historical metadata.
The static response-file setting names a file that was not supplied; static mode
has no BLOCK response samples.

- [PROJECT_REPORT.md](PROJECT_REPORT.md): implementation, measurements and limitations.
- [PROJECT_COMPATIBILITY.md](PROJECT_COMPATIBILITY.md): historical integration contract.
- [AUDIT_REPORT.md](AUDIT_REPORT.md): cleanup scope and validation results.
- `network/benchmark.py`: optional benchmark helper called from the Mininet CLI.

Do not rerun performance benchmarks just to view results. The benchmark helper's
`--summarize` option writes a new comparison CSV; read saved CSVs directly when
only inspecting evidence. Newly generated settings may record absolute output
paths, and iperf embeds the current hostname: audit new results before publishing.

## Scope and safety

Use an isolated, authorized lab. This is a fixed-topology teaching prototype.
It is not a production firewall: it has no general IPv6/UDP inspection, logging
uses unauthenticated plain TCP, event delivery has finite retries, and approved
flow rules do not expire. See the report for further limits. No runtime event
database, Git history, virtual environment or personal account configuration is
included. Choose a license with all contributors before adding licensing terms.
