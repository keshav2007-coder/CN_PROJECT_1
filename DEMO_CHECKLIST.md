# Demonstration Checklist

Use `IMPLEMENTATION_GUIDE.md` for the three-terminal startup commands. This is a manual demonstration checklist, not an automated launcher. Present the saved benchmarks instead of rerunning them.

## Start and connect

- [ ] Open terminals at the project root; confirm ports 9000 and 6653 are free.
- [ ] Start the real logger with a new isolated database and retain its run-directory name.
- [ ] Start OS-Ken in dynamic mode; confirm `dependencies=real`.
- [ ] Start the existing topology, then H4's application server on `0.0.0.0:5000`, retaining the `app` process handle.
- [ ] In Mininet, run `nodes`, `net`, and the following connection check; expect `true`:

```text
sh ovs-vsctl get Controller s1 is_connected
```

## Show authorized requests and concurrency

- [ ] Send authorized requests from H1, H2 and H3; show matching ACKs:

```text
h1 python3 -B apps/client.py --host 10.0.0.10 --port 5000 --message H1 --timeout 2
h2 python3 -B apps/client.py --host 10.0.0.10 --port 5000 --message H2 --timeout 2
h3 python3 -B apps/client.py --host 10.0.0.10 --port 5000 --message H3 --timeout 2
```

- [ ] Launch three clients before waiting for their captured output. Confirm each receives its own ACK:

```text
px clients = [(h, net.get(h).popen(['python3', '-B', 'apps/client.py', '--host', '10.0.0.10', '--port', '5000', '--message', h+'-concurrent', '--timeout', '2'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)) for h in ('h1', 'h2', 'h3')]
py print('\n'.join(h+':\n'+p.communicate(timeout=10)[0].decode() for h,p in clients))
```

`subprocess` is imported during application startup in the implementation guide. Check actual ACK text; the client can exit normally after a failed request.

## Show denial and automatic blocking

- [ ] Run one batch of three distinct unauthorized attempts. Use a fresh source-port range if repeating:

```text
h2 python3 -B apps/traffic.py --host 10.0.0.10 --port 5001 --attempts 3 --timeout 1 --interval 1 --source-port-start 46000
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

- [ ] Show `priority=400`, source `10.0.0.2`, `hard_timeout=30` and `actions=drop`. Explain that lower-priority exact DENY rules cover individual unauthorized connections.
- [ ] Promptly show H2's approved application access fails while H3 still receives an ACK, before the block expires:

```text
h2 python3 -B apps/client.py --host 10.0.0.10 --port 5000 --message blocked --timeout 2
h3 python3 -B apps/client.py --host 10.0.0.10 --port 5000 --message unaffected --timeout 2
```

## Show recovery and stored security events

- [ ] Wait beyond expiry, then show the source block is gone and H2 receives an ACK:

```text
sh sleep 32
sh ovs-ofctl -O OpenFlow13 dump-flows s1
h2 python3 -B apps/client.py --host 10.0.0.10 --port 5000 --message recovered --timeout 2
```

- [ ] Show DENY, BLOCK and RECOVER on the logger and matching delivery confirmations on the controller.
- [ ] Retrieve committed events from the current database in Mininet's root-namespace shell:

```text
sh python3 -B security/view_logs.py --db "$RUN_DIR/events.db"
```

- [ ] Explain that the cookie associates BLOCK with recovery, and repeated event IDs are deduplicated. A queued event alone is not proof of storage.

## Present saved results

- [ ] Display the saved comparison and dynamic controller-response values:

```text
sh cat benchmark-results.GHxubQ/comparison-0b5ee436.csv
sh cat benchmark-results.GHxubQ/dynamic-response.csv
```

- [ ] Explain 90/90 successful H3 requests per condition, three 10-second throughput trials per condition, static reachability, dynamic blocking and recovered reachability.
- [ ] Distinguish TCP RTT from the mean 1.031 ms BarrierReply response. Explain that local virtual-network throughput is not physical-link capacity and RTT was measured with simultaneous iperf load.
- [ ] Use the formatted table and known limitations in `PROJECT_REPORT.md` for questions. Static-mode results are saved evidence; a live mode switch requires restarting both controller and topology.

## Stop safely

- [ ] Confirm RECOVER is stored, then stop the application started for this session and exit Mininet:

```text
py app.send_signal(2)
py app.wait(timeout=5)
exit
```

- [ ] Stop the controller, then logger, using Ctrl+C in their own terminals.
- [ ] Verify this session's listeners are gone; preserve the new evidence directory and existing benchmark files.
