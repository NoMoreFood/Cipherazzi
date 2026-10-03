import argparse
import hashlib
import json
import platform
from pathlib import Path
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--optimized', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repetitions', type=int, default=7)
    parser.add_argument('--loopback', action='store_true', help='Include live capture; requires elevation')
    args = parser.parse_args()
    assert 3 <= args.repetitions <= 20
    executables = {'baseline': args.baseline.resolve(), 'optimized': args.optimized.resolve()}
    result = dict(system=platform.platform(), processor=platform.processor(), binaries={
        name: dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        for name, path in executables.items()}, trials=[], summary={})
    workloads = [('evidence', '100000')]
    if args.loopback:
        workloads.extend([('loopback', '100000'), ('loopback', '100000', 'burst'), ('loopback', '20000', 'mixed'),
            ('loopback', '100000', 'concurrent')])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    expected = {}

    # Alternate ordering and exclude one warmup per executable/workload; verify identical observable results.
    for iteration in range(args.repetitions + 1):
        order = list(executables) if iteration % 2 == 0 else list(reversed(executables))
        for workload in workloads:
            for name in order:
                process = subprocess.run([str(executables[name]), *workload], capture_output=True, text=True,
                    timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
                if process.returncode:
                    raise RuntimeError(f'{name} {workload}: {process.stderr or process.stdout}')
                measured = json.loads(process.stdout)
                rows = measured['measurements']
                if isinstance(rows, dict):
                    rows = [rows]
                for row in rows:
                    # WinDivert can deliver UDP out of sequence; coverage and timestamp bounds are checked natively.
                    identity = {key: value for key, value in row.items() if key not in
                        ('elapsed_ms', 'cpu_ms', 'io_operations', 'driver_order_reversals',
                         'driver_timestamp_reversals')}
                    key = row['workload']
                    assert identity == expected.setdefault(key, identity), f'{key}: observable results changed'
                    if iteration:
                        result['trials'].append(dict(build=name, iteration=iteration,
                            peak_working_set_bytes=measured['peak_working_set_bytes'], **row))
                    print(f'{iteration}: {name} {key}: {row["elapsed_ms"]:.2f} ms, '
                          f'{row["cpu_ms"]:.2f} CPU ms', flush=True)
                args.output.write_text(json.dumps(result, indent=2))
    for workload in expected:
        summary = {}
        metrics = ['elapsed_ms', 'cpu_ms', 'peak_working_set_bytes']
        if workload.endswith('_loopback'):
            metrics.append('io_operations')
        for metric in metrics:
            values = {name: [row[metric] for row in result['trials']
                if row['build'] == name and row['workload'] == workload] for name in executables}
            medians = {name: statistics.median(samples) for name, samples in values.items()}
            summary[metric] = dict(medians=medians, minimum={name: min(samples) for name, samples in values.items()},
                maximum={name: max(samples) for name, samples in values.items()},
                reduction_percent=100 * (1 - medians['optimized'] / medians['baseline'])
                if medians['baseline'] else None)
        result['summary'][workload] = summary
    result['equivalent_results'] = True
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result['summary'], indent=2))


if __name__ == '__main__':
    main()
