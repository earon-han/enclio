#!/usr/bin/env python3
"""Measured-duration Enclio stability runner; default is a real 24-hour run.

Run under a delegated user service/scope, or an outer-limited Docker container.
The summary says complete only after monotonic elapsed time reaches the request.
JSONL samples are flushed after each round, so interrupted runs remain auditable.
"""
import argparse
import concurrent.futures
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="build/enclio")
    parser.add_argument("--duration", type=float, default=86400)
    parser.add_argument("--interval", type=float, default=30)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--network-every", type=int, default=4,
                        help="run the controlled production-timing network suite every N rounds; 0 disables")
    parser.add_argument("--cgroup-parent")
    parser.add_argument("--prepare-delegation", action="store_true")
    parser.add_argument("--output", default="build/soak")
    args = parser.parse_args()
    if (not math.isfinite(args.duration) or not math.isfinite(args.interval) or
            args.duration <= 0 or args.interval < 0 or args.network_every < 0 or not 1 <= args.workers <= 32):
        parser.error("duration/workers must be positive and interval nonnegative")
    binary = str(Path(args.binary).resolve())
    output = Path(args.output).resolve(); output.mkdir(parents=True, exist_ok=True)
    if any((output / name).exists() for name in ("metadata.json", "samples.jsonl", "summary.json")):
        parser.error("output contains a prior run; choose a new directory to preserve raw evidence")
    identity = json.loads(subprocess.check_output(["python3", "scripts/source-id.py", "--json"], text=True))
    binary_sha = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    parent = Path(args.cgroup_parent) if args.cgroup_parent else None
    if args.prepare_delegation:
        if parent:
            parser.error("--prepare-delegation discovers its own delegated cgroup; do not combine with --cgroup-parent")
        relative = next(line.split(":", 2)[2] for line in Path("/proc/self/cgroup").read_text().splitlines()
                        if line.startswith("0::"))
        parent = Path("/sys/fs/cgroup") / relative.lstrip("/")
        control = parent / "control"; control.mkdir(exist_ok=True)
        (control / "cgroup.procs").write_text(str(os.getpid()))
        (parent / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    stopped = False
    def stop(_signal, _frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    started = time.monotonic(); rounds = 0; failures = 0; samples = 0
    network_runs = 0; network_checks = 0
    previous_round = previous_wall = None
    max_gap = 0.0
    expected_rounds = math.ceil(args.duration / args.interval) if args.interval > 0 else None
    minimum_rounds = math.floor(expected_rounds * 0.9) if args.duration >= 3600 and expected_rounds else 1
    gap_limit = max(120.0, args.interval * 4) if args.duration >= 3600 and args.interval > 0 else None
    metadata = dict(schema_version=1, source_identity=identity, binary_sha256=binary_sha,
                    requested_seconds=args.duration, interval_seconds=args.interval,
                    concurrency=args.workers, aggregate_limits_requested=bool(parent),
                    network_every_rounds=args.network_every, network_production_timing=True,
                    expected_rounds=expected_rounds, minimum_rounds=minimum_rounds,
                    maximum_round_gap_seconds=gap_limit,
                    wall_start=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    def task(number):
        begin = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="enclio-soak-task-") as temporary:
            root = Path(temporary); workspace = root / "workspace"; workspace.mkdir()
            report = root / "result.json"
            mode = number % 4
            command = [binary, "run", "--workspace", str(workspace), "--timeout", "10",
                       "--result", str(report)]
            if parent:
                command += ["--cgroup-parent", str(parent), "--memory-bytes", "67108864",
                            "--pids-max", "32", "--cpu-percent", "100"]
            if mode == 0:
                command += ["--", "/bin/sh", "-c", "echo PROBE_EXECUTED; printf stable"]
                expected, status = 0, "exited"
            elif mode == 1:
                destination = root / "export"; destination.mkdir()
                command += ["--workspace-mode", "tmpfs", "--disk-bytes", "4194304", "--export", str(destination),
                            "--", "/bin/sh", "-c", "echo PROBE_EXECUTED; echo durable > /workspace/output"]
                expected, status = 0, "exited"
            elif mode == 2:
                command += ["--output-bytes", "1024", "--", "/bin/sh", "-c",
                            "echo PROBE_EXECUTED; yes output"]
                expected, status = 126, "resource_limit"
            else:
                command += ["--", "/usr/bin/python3", "-c",
                            "import threading,subprocess; print('PROBE_EXECUTED',flush=True); "
                            "t=threading.Thread(target=lambda:subprocess.run(['/bin/true'],check=True)); t.start(); t.join()"]
                expected, status = 0, "exited"
            try:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=20)
                result = json.loads(report.read_text()) if report.exists() and report.stat().st_size else {}
                passed = (proc.returncode == expected and result.get("status") == status and
                          result.get("command_started") and result.get("cleanup_complete") and
                          "PROBE_EXECUTED" in proc.stdout)
                if mode == 1:
                    passed = passed and (destination / "output").read_text() == "durable\n"
                if mode == 2:
                    passed = passed and result.get("limit_reason") == "output"
                return dict(task=number, mode=mode, passed=bool(passed), returncode=proc.returncode,
                            duration_ms=round((time.monotonic()-begin)*1000, 3), result=result,
                            stderr=proc.stderr[:4096])
            except Exception as error:
                return dict(task=number, mode=mode, passed=False, error=repr(error))
    with (output / "samples.jsonl").open("a", buffering=1) as raw:
        while not stopped and time.monotonic() - started < args.duration:
            beginning = time.monotonic()
            wall = time.time()
            if previous_round is not None:
                gap = max(beginning-previous_round, wall-previous_wall)
                max_gap = max(max_gap, gap)
                if gap_limit is not None and gap > gap_limit:
                    failures += 1
                    raw.write(json.dumps(dict(type="fatal", error="sample gap exceeded coverage bound",
                                              gap_seconds=round(gap, 3))) + "\n")
                    break
            previous_round, previous_wall = beginning, wall
            if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != binary_sha:
                raw.write(json.dumps(dict(type="fatal", error="tested binary changed")) + "\n")
                failures += 1; break
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
                results = list(executor.map(task, range(samples, samples + args.workers)))
            rounds += 1; samples += len(results)
            failures += sum(not r["passed"] for r in results)
            if parent:
                leftover = sorted(p.name for p in parent.glob("enclio-*") if p.is_dir())
                if leftover:
                    failures += 1
                    results.append(dict(passed=False, error="cgroup residual", groups=leftover))
            network = None
            if args.network_every and rounds % args.network_every == 0:
                report = output / f"network-{rounds}.json"
                try:
                    proc = subprocess.run(["python3", "tests/network_integration.py", "--output", str(report)],
                                          capture_output=True, text=True, timeout=120)
                    evidence = json.loads(report.read_text()) if report.exists() else {}
                    good = (proc.returncode == 0 and evidence.get("failed") == 0 and
                            evidence.get("production_timing") is True and
                            evidence.get("source_identity", {}).get("source_tree_sha256") == identity["source_tree_sha256"])
                    network_runs += 1; network_checks += len(evidence.get("results", []))
                    if not good: failures += 1
                    network = dict(passed=good, report=report.name, returncode=proc.returncode,
                                   fixture_sha256=evidence.get("fixture_sha256"),
                                   checks=len(evidence.get("results", [])), stderr=proc.stderr[-4096:])
                except Exception as error:
                    failures += 1; network = dict(passed=False, error=repr(error))
            raw.write(json.dumps(dict(round=rounds, elapsed_seconds=round(time.monotonic()-started, 3),
                                      wall_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(wall)),
                                      samples=results, network=network)) + "\n")
            raw.flush(); os.fsync(raw.fileno())
            current = json.loads(subprocess.check_output(["python3", "scripts/source-id.py", "--json"], text=True))
            if failures:
                break
            if current["source_tree_sha256"] != identity["source_tree_sha256"]:
                failures += 1
                raw.write(json.dumps(dict(type="fatal", error="execution or validation inputs changed")) + "\n")
                break
            remaining = min(args.interval - (time.monotonic()-beginning), args.duration - (time.monotonic()-started))
            if remaining > 0:
                time.sleep(remaining)
    elapsed = time.monotonic() - started
    if previous_round is not None:
        tail_gap = max(time.monotonic()-previous_round, time.time()-previous_wall)
        max_gap = max(max_gap, tail_gap)
        if gap_limit is not None and tail_gap > gap_limit:
            failures += 1
            with (output / "samples.jsonl").open("a") as raw:
                raw.write(json.dumps(dict(type="fatal", error="final sample gap exceeded coverage bound",
                                          gap_seconds=round(tail_gap, 3))) + "\n")
    summary = dict(**metadata, observed_seconds=round(elapsed, 3), rounds=rounds,
                   samples=samples, network_runs=network_runs, network_checks=network_checks,
                   failures=failures, interrupted=stopped, max_round_gap_seconds=round(max_gap, 3),
                   coverage_sufficient=rounds >= minimum_rounds and (gap_limit is None or max_gap <= gap_limit),
                   complete=elapsed >= args.duration and not stopped and failures == 0 and
                            rounds >= minimum_rounds and (gap_limit is None or max_gap <= gap_limit),
                   wall_finish=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return 0 if summary["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
