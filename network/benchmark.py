"""Call run(net, mode, output_root, response_csv) from the Mininet Python CLI.

Restart controller AND topology before changing modes. This helper never changes
controller mode, deletes flows, starts Mininet, or starts the application server.
RTT includes TCP connect + request/ACK, as in apps.client, but no process startup.
H3 RTT and throughput run concurrently in every condition (same offered load).
"""

import argparse
import contextlib
import csv
from datetime import datetime, timezone
import io
import json
import math
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ['condition', 'trial', 'metric', 'sample', 'value', 'unit', 'status', 'detail']
SUMMARY = ['condition', 'rtt_successes', 'rtt_expected', 'rtt_mean_ms',
           'rtt_p95_ms', 'throughput_successes', 'throughput_mean_mbps',
           'h2_state', 'block_response_mean_ms', 'status']


def stats(values):
    return (statistics.mean(values), sorted(values)[math.ceil(.95 * len(values)) - 1]) if values else ('', '')


def rtt_worker(count):
    sys.path.insert(0, str(ROOT))
    from apps.client import send_request
    samples = []
    for i in range(count):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            value, ack = send_request('10.0.0.10', 5000, 'benchmark', 1)
        samples.append({'ms': value, 'ok': value is not None and ack == 'ACK: benchmark',
                        'detail': captured.getvalue().strip()})
        if i + 1 < count:
            time.sleep(.2)
    print(json.dumps(samples))


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def collect(process, timeout):
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop(process)
        output, _ = process.communicate(timeout=3)
        raise RuntimeError('Process timed out: ' + output.decode(errors='replace')[-300:])
    text = output.decode(errors='replace')
    if process.returncode:
        raise RuntimeError(text[-500:])
    return text


def launch(host, args):
    return host.popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def command(host, args, timeout=5):
    return collect(launch(host, args), timeout)


def flows(net):
    return command(net.get('s1'), ['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'])


def block_cookie(text):
    for line in text.splitlines():
        if 'priority=400' in line and 'nw_src=10.0.0.2' in line and 'actions=drop' in line:
            match = re.search(r'cookie=(0x[0-9a-fA-F]+)', line)
            if match:
                return str(int(match[1], 16))
    return None


def h2_ack(net):
    text = command(net.get('h2'), ['python3', '-B', str(ROOT / 'apps/client.py'),
                   '--host', '10.0.0.10', '--port', '5000', '--timeout', '1',
                   '--message', 'H2-state'], 5)
    return 'ACK: H2-state' in text


def write_csv(path, fields, rows):
    with path.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def summarize_rows(rows, conditions):
    summaries = []
    for condition in conditions:
        subset = [r for r in rows if r['condition'] == condition]
        rtts = [float(r['value']) for r in subset if r['metric'] == 'rtt' and r['status'] == 'PASS']
        rates = [float(r['value']) for r in subset if r['metric'] == 'throughput' and r['status'] == 'PASS']
        states = [r for r in subset if r['metric'] == 'h2_state']
        responses = [float(r['value']) for r in subset
                     if r['metric'] == 'block_response' and r['status'] == 'PASS']
        mean, p95 = stats(rtts)
        complete = len(rtts) == 90 and len(rates) == 3 and len(states) == 3
        summaries.append(dict(zip(SUMMARY, [condition, len(rtts), 90, mean, p95,
            len(rates), statistics.mean(rates) if rates else '',
            '; '.join(sorted({r['detail'] for r in states})) or 'UNVERIFIED',
            statistics.mean(responses) if responses else '',
            'PASS' if complete and all(r['status'] == 'PASS' for r in subset) else 'INCOMPLETE/FAIL'])))
    return summaries


def run(net, mode, output_root, response_csv):
    """Three trials per condition; dynamic also measures recovered condition.

    mode is a label/assertion by the operator, NOT a controller configuration.
    Each trial saves 30 H3 RTTs and one 10s receiver throughput measurement.
    """
    if mode not in ('static', 'dynamic'):
        raise ValueError('mode must be static or dynamic')
    output = Path(output_root).resolve() / (mode + '-' + uuid.uuid4().hex[:10])
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    processes = []
    used_ports = set()
    conditions = [mode] + (['recovered'] if mode == 'dynamic' else [])
    response_path = Path(response_csv).resolve()
    known_cookies = set()
    if response_path.exists():
        with response_path.open(newline='') as stream:
            known_cookies = {r['cookie'] for r in csv.DictReader(stream)}
    (output / 'settings.json').write_text(json.dumps({
        'utc': datetime.now(timezone.utc).isoformat(), 'operator_selected_mode': mode,
        'rtt_per_trial': 30, 'rtt_spacing_seconds': .2, 'trials': 3,
        'iperf_seconds': 10, 'throughput_statistic': 'receiver Mbps',
        'load': 'H3 RTT concurrent with H3 iperf in every trial',
        'response_csv': str(response_path), 'p95': 'nearest rank',
        'rtt_definition': 'TCP connect plus request/ACK; excludes interpreter startup',
    }, indent=2), encoding='utf-8')

    def record(condition, trial, metric, sample='', value='', unit='', ok=True, detail=''):
        rows.append(dict(zip(FIELDS, [condition, trial, metric, sample, value, unit,
                                     'PASS' if ok else 'FAIL', detail])))

    def wait_recovered():
        deadline = time.monotonic() + 36
        while block_cookie(flows(net)) is not None:
            if time.monotonic() > deadline:
                raise RuntimeError('H2 block did not expire within 36 seconds')
            time.sleep(1)
        if not h2_ack(net):
            raise RuntimeError('H2 did not receive ACK after block removal')

    try:
        if block_cookie(flows(net)) is not None:
            raise RuntimeError('Stale H2 block: restart topology and controller first')
        if not h2_ack(net):
            raise RuntimeError('H2 application preflight failed')
        h3 = net.get('h3')
        h4 = net.get('h4')
        if command(h4, ['ss', '-H', '-ltn', 'sport = :5201']).strip():
            raise RuntimeError('H4:5201 occupied; stop only your previous iperf server')
        server_log = (output / 'iperf-server.log').open('x')
        try:
            server = h4.popen(['iperf3', '-s', '-B', '10.0.0.10', '-p', '5201'],
                              stdout=server_log, stderr=subprocess.STDOUT)
            processes.append(server)
            deadline = time.monotonic() + 5
            while not command(h4, ['ss', '-H', '-ltn', 'sport = :5201']).strip():
                if server.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('iperf3 server failed to start')
                time.sleep(.1)
            for condition in conditions:
                for trial in range(1, 4):
                    if mode == 'dynamic':
                        wait_recovered()
                    print(f'{condition}: trial {trial}/3', flush=True)
                    # Warm the application path consistently before each trial.
                    warm = command(h3, ['python3', '-B', str(__file__), '--rtt-worker', '1'])
                    if not json.loads(warm)[0]['ok']:
                        raise RuntimeError('H3 warm-up failed')
                    rate = launch(h3, ['iperf3', '-c', '10.0.0.10', '-p', '5201',
                                       '-t', '10', '-J', '--connect-timeout', '2000'])
                    rtt = launch(h3, ['python3', '-B', str(__file__), '--rtt-worker', '30'])
                    processes.extend([rate, rtt])
                    attack = None
                    if condition != 'recovered':
                        # Sequential connect timeout + interval gives ~2s spacing.
                        ports = 40000 + int(uuid.uuid4().hex[:6], 16) % 20000
                        while used_ports.intersection(range(ports, ports + 3)):
                            ports = 40000 + int(uuid.uuid4().hex[:6], 16) % 20000
                        used_ports.update(range(ports, ports + 3))
                        attack = launch(net.get('h2'), ['python3', '-B', str(ROOT / 'apps/traffic.py'),
                            '--host', '10.0.0.10', '--port', '5001', '--attempts', '3',
                            '--timeout', '1', '--interval', '1', '--source-port-start', str(ports)])
                        processes.append(attack)
                        attack_text = collect(attack, 8)
                        (output / f'{condition}-{trial}-attack.txt').write_text(attack_text)
                        if attack_text.count('[TIMEOUT]') != 3:
                            raise RuntimeError('Unauthorized attempts were not three timeouts; inspect attack output')
                    snapshot = flows(net)
                    (output / f'{condition}-{trial}-flows.txt').write_text(snapshot)
                    cookie = block_cookie(snapshot)
                    ack = h2_ack(net)
                    expected_block = condition == 'dynamic'
                    state_ok = bool(cookie) == expected_block and ack != expected_block
                    record(condition, trial, 'h2_state', ok=state_ok,
                           detail=('blocked' if cookie and not ack else
                                   'reachable' if not cookie and ack else 'inconsistent'))
                    try:
                        samples = json.loads(collect(rtt, 45))
                        if len(samples) != 30:
                            raise ValueError('Expected 30 RTT samples')
                        for i, sample in enumerate(samples, 1):
                            record(condition, trial, 'rtt', i,
                                   sample['ms'] if sample['ok'] else '', 'ms',
                                   sample['ok'], sample['detail'])
                    except (RuntimeError, ValueError, KeyError) as error:
                        record(condition, trial, 'rtt', ok=False, detail=str(error))
                    try:
                        raw = collect(rate, 18)
                        (output / f'{condition}-{trial}-iperf.json').write_text(raw)
                        data = json.loads(raw)
                        if 'error' in data:
                            raise ValueError(data['error'])
                        received = data['end']['sum_received']
                        seconds = float(received['seconds'])
                        mbps = float(received['bits_per_second']) / 1e6
                        if not math.isfinite(mbps) or mbps <= 0 or not 9 <= seconds <= 12:
                            raise ValueError('Invalid throughput value or duration')
                        record(condition, trial, 'throughput', trial, mbps, 'Mbps',
                               detail=f'receiver duration={seconds}')
                    except (RuntimeError, ValueError, KeyError) as error:
                        record(condition, trial, 'throughput', ok=False, detail=str(error))
                    if condition == 'dynamic':
                        matching = []
                        if response_path.exists():
                            with response_path.open(newline='') as stream:
                                matching = [r for r in csv.DictReader(stream)
                                    if r['src_ip'] == '10.0.0.2' and r['cookie'] == cookie
                                    and r['cookie'] not in known_cookies]
                        value = float(matching[-1]['response_ms']) if matching else ''
                        record(condition, trial, 'block_response', value=value, unit='ms',
                               ok=bool(matching), detail=f'BarrierReply cookie={cookie}')
                    if not state_ok:
                        raise RuntimeError('H2 state contradicts requested condition; check real controller mode')
        finally:
            for process in processes:
                stop(process)
            server_log.close()
    except Exception as error:
        record(mode, '', 'error', ok=False, detail=str(error))
        print('BENCHMARK FAILED:', error, flush=True)
    finally:
        for process in processes:
            stop(process)
        write_csv(output / 'measurements.csv', FIELDS, rows)
        summaries = summarize_rows(rows, conditions)
        write_csv(output / 'summary.csv', SUMMARY, summaries)
        for summary in summaries:
            print(summary)
        print('Results:', output, flush=True)
    return str(output)


def comparison(root):
    rows = []
    for path in sorted(Path(root).glob('*/summary.csv')):
        with path.open(newline='') as stream:
            rows.extend(dict(r, run=path.parent.name) for r in csv.DictReader(stream))
    target = Path(root) / ('comparison-' + uuid.uuid4().hex[:8] + '.csv')
    write_csv(target, ['run'] + SUMMARY, rows)
    print('condition | RTT mean ms | RTT p95 ms | throughput Mbps | H2 | block response ms | status')
    for r in rows:
        print(' | '.join(r[k] or 'MISSING' for k in
              ('condition', 'rtt_mean_ms', 'rtt_p95_ms', 'throughput_mean_mbps',
               'h2_state', 'block_response_mean_ms', 'status')))
    print(target)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--rtt-worker', type=int, choices=(1, 30), help=argparse.SUPPRESS)
    group.add_argument('--summarize', metavar='OUTPUT_ROOT')
    args = parser.parse_args()
    if args.rtt_worker:
        rtt_worker(args.rtt_worker)
    else:
        comparison(args.summarize)
