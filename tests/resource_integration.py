#!/usr/bin/env python3
"""Independent CLI-level resource, managed filesystem and cleanup validation.

Run aggregate exhaustion cases inside an outer test scope/container with a
MemoryMax/TasksMax safety net. A requested cgroup limit without delegation must
fail before the payload. All enforcement negatives require an execution marker.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import signal
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="build/enclio")
    parser.add_argument("--cgroup-parent")
    parser.add_argument("--output", default="build/resource-integration.json")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    results = []
    def record(name, success, **detail):
        results.append(dict(name=name, status="PASS" if success else "FAIL", **detail))
        print(results[-1]["status"] + ": " + name, flush=True)
    with tempfile.TemporaryDirectory(prefix="enclio-resource-tests-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"; workspace.mkdir()
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "tests/resource_probe.c", "-o", str(workspace / "probe")], check=True)
        index = 0
        def run(name, command, options=(), expected=0, status="exited", reason=None,
                started=True, check=None, timeout=15):
            nonlocal index
            index += 1; report = root / f"result-{index}.json"
            argv = [binary, "run", "--workspace", str(workspace), "--timeout", "8",
                    "--result", str(report), *options, "--", *command]
            proc = subprocess.run(argv, capture_output=True, timeout=timeout)
            data = json.loads(report.read_text()) if report.exists() and report.stat().st_size else {}
            stdout, stderr = proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace")
            good = (proc.returncode == expected and data.get("status") == status and
                    data.get("command_started") is started and data.get("cleanup_complete") is True)
            if started:
                good = good and "PROBE_EXECUTED" in stdout
            if reason is not None:
                good = good and data.get("limit_reason") == reason
            if check:
                good = good and bool(check(data, proc))
            record(name, good, returncode=proc.returncode, stdout=stdout[:8192], stderr=stderr[:8192], result=data)
            return proc, data
        run("strict_unknown_syscall_denied", ["/workspace/probe", "strict-unknown"])
        run("compat_unknown_syscall_available", ["/workspace/probe", "compat-unknown"], ["--seccomp", "compat"])
        if platform.machine() == "x86_64":
            run("compat_abi_killed", ["/workspace/probe", "compat-abi"], expected=159,
                check=lambda d, p: d.get("signal") == signal.SIGSYS)
        run("python_threads_strict", ["/usr/bin/python3", "-c",
            "import threading,subprocess; print('PROBE_EXECUTED',flush=True); t=threading.Thread(target=lambda: subprocess.run(['/bin/true'],check=True)); t.start(); t.join()"])
        (workspace / "hello.c").write_text('#include <stdio.h>\nint main(void){puts("COMPILED_IN_SANDBOX");return 0;}\n')
        run("native_compiler_strict", ["/bin/sh", "-c",
            "echo PROBE_EXECUTED; cc /workspace/hello.c -o /workspace/hello && /workspace/hello"],
            check=lambda d, p: b"COMPILED_IN_SANDBOX" in p.stdout)
        run("git_workspace_strict", ["/bin/sh", "-c", "echo PROBE_EXECUTED; git init -q /workspace/repo && git -C /workspace/repo status --porcelain"])
        run("open_file_rlimit", ["/workspace/probe", "files"], ["--open-files", "48"])
        run("address_space_rlimit", ["/workspace/probe", "address"], ["--address-space-bytes", "33554432"])
        run("single_file_rlimit", ["/workspace/probe", "file-size"], ["--file-bytes", "16384"],
            check=lambda d, p: (workspace / "large-file").stat().st_size <= 16384)
        run("cpu_time_rlimit", ["/workspace/probe", "cpu"], ["--cpu-seconds", "1"],
            expected=126, status="resource_limit", reason="cpu")
        proc, data = run("aggregate_output_budget", ["/workspace/probe", "output"], ["--output-bytes", "4096"],
                         expected=126, status="resource_limit", reason="output",
                         check=lambda d, p: len(p.stdout) + len(p.stderr) <= 4096 and d.get("output_bytes") == 4096)
        # Caller signal state must not disable cancellation/reaping or the
        # default resource-limit signals delivered to a newly exec'd payload.
        def inherited_signals(name, command, *, ignored=None, blocked=(), options=(),
                              cancel=False, expected=0, status="exited", reason="", expected_signal=0):
            report = root / (name + ".json")
            def caller_signal_state():
                if ignored is not None:
                    signal.signal(ignored, signal.SIG_IGN)
                if blocked:
                    signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
            proc = subprocess.Popen([binary, "run", "--workspace", str(workspace),
                                     "--timeout", "6", "--result", str(report),
                                     *options, "--", *command], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, preexec_fn=caller_signal_state)
            marker = b""
            if cancel:
                if select.select([proc.stdout], [], [], 3)[0]:
                    marker = proc.stdout.readline()
                begin = time.monotonic()
                if proc.poll() is None:
                    proc.send_signal(signal.SIGTERM)
            else:
                begin = time.monotonic()
            expired = False
            try:
                out, err = proc.communicate(timeout=4 if cancel else 9)
            except subprocess.TimeoutExpired:
                expired = True
                proc.kill()
                out, err = proc.communicate(timeout=5)
            elapsed = time.monotonic() - begin
            data = json.loads(report.read_text()) if report.exists() and report.stat().st_size else {}
            stdout = marker + out
            good = (not expired and proc.returncode == expected and
                    b"PROBE_EXECUTED" in stdout and data.get("status") == status and
                    data.get("command_started") is True and data.get("cleanup_complete") is True and
                    data.get("limit_reason") == reason and data.get("signal") == expected_signal)
            if cancel:
                good = good and elapsed < 3
            elif expected == 0:
                good = good and data.get("command_exit_code") == 0
            record(name, good, returncode=proc.returncode, expired=expired,
                   elapsed_after_signal_seconds=round(elapsed, 3) if cancel else None,
                   stdout=stdout.decode(errors="replace"), stderr=err.decode(errors="replace"), result=data)
        inherited_signals("inherited_blocked_signals_do_not_disable_cancellation",
                          ["/bin/sh", "-c", "echo PROBE_EXECUTED; sleep 20"],
                          blocked={signal.SIGTERM, signal.SIGCHLD, signal.SIGALRM}, cancel=True,
                          expected=143, status="cancelled", expected_signal=signal.SIGTERM)
        inherited_signals("inherited_ignored_SIGCHLD_does_not_disable_reaping",
                          ["/bin/sh", "-c", "echo PROBE_EXECUTED; exit 0"], ignored=signal.SIGCHLD)
        inherited_signals("inherited_ignored_SIGXCPU_restores_default_limit_signal",
                          ["/bin/sh", "-c", "echo PROBE_EXECUTED; while :; do :; done"],
                          ignored=signal.SIGXCPU, options=["--cpu-seconds", "1"],
                          expected=126, status="resource_limit", reason="cpu", expected_signal=signal.SIGXCPU)
        inherited_signals("inherited_ignored_SIGXFSZ_restores_default_limit_signal",
                          ["/bin/sh", "-c", "echo PROBE_EXECUTED; exec /usr/bin/yes data > /workspace/signal-limited-file"],
                          ignored=signal.SIGXFSZ, options=["--file-bytes", "4096"],
                          expected=126, status="resource_limit", reason="file", expected_signal=signal.SIGXFSZ)
        run("exec_failure_is_not_output_limit_with_tiny_budget", ["/does-not-exist"],
            ["--output-bytes", "1"], expected=125, status="setup_error", started=False, reason="",
            check=lambda d, p: d.get("command_exit_code") == -1 and d.get("output_bytes") == 0 and
                  len(p.stderr) > 1 and b"enclio:" in p.stderr)
        run("initialization_failure_is_not_output_limit_with_tiny_budget", ["/bin/true"],
            ["--cwd", "/workspace/missing", "--output-bytes", "1"],
            expected=125, status="setup_error", started=False, reason="",
            check=lambda d, p: d.get("command_exit_code") == -1 and d.get("output_bytes") == 0 and
                  len(p.stderr) > 1 and b"enclio:" in p.stderr)
        # A marker in the authorized workspace proves execution independently
        # of the one-byte output budget. Fast stderr must confirm exec too.
        stderr_only = []
        for attempt in range(10):
            marker_path = workspace / ("stderr-executed-" + str(attempt))
            report = root / ("stderr-only-" + str(attempt) + ".json")
            proc = subprocess.run([binary, "run", "--workspace", str(workspace), "--timeout", "4",
                                   "--output-bytes", "1", "--result", str(report), "--", "/bin/sh", "-c",
                                   "printf ran > /workspace/" + marker_path.name +
                                   "; printf stderr-only-overflow >&2"],
                                  capture_output=True, timeout=8)
            data = json.loads(report.read_text()) if report.exists() and report.stat().st_size else {}
            executed = marker_path.exists() and marker_path.read_bytes() == b"ran"
            good = (executed and proc.returncode == 126 and data.get("status") == "resource_limit" and
                    data.get("limit_reason") == "output" and data.get("command_started") is True and
                    data.get("cleanup_complete") is True and data.get("output_bytes") == 1 and
                    not proc.stdout and len(proc.stderr) <= 1)
            stderr_only.append(dict(attempt=attempt, passed=good, executed=executed,
                                    returncode=proc.returncode, stdout=proc.stdout.decode(errors="replace"),
                                    stderr=proc.stderr.decode(errors="replace"), result=data))
            marker_path.unlink(missing_ok=True)
        record("fast_stderr_only_over_budget_confirms_execution", all(r["passed"] for r in stderr_only),
               iterations=stderr_only)
        run("readonly_workspace", ["/bin/sh", "-c", "echo PROBE_EXECUTED; ! touch /workspace/denied"], ["--workspace-mode", "readonly"],
            check=lambda d, p: not (workspace / "denied").exists())
        # A clean input directory leaves room to inspect the common writable fs.
        for name in ("large-file", "hello", "hello.c"):
            (workspace / name).unlink(missing_ok=True)
        run("managed_disk_has_no_tmp_home_dev_shm_bypass", ["/workspace/probe", "disk"],
            ["--workspace-mode", "tmpfs", "--disk-bytes", "4194304"])
        destination = root / "export"; destination.mkdir()
        run("managed_workspace_export", ["/bin/sh", "-c",
            "echo PROBE_EXECUTED; test -f /input/probe && echo exported > /workspace/result"],
            ["--workspace-mode", "tmpfs", "--disk-bytes", "4194304", "--export", str(destination)],
            check=lambda d, p: (destination / "result").read_text() == "exported\n")
        sparse_export = root / "sparse-export"; sparse_export.mkdir()
        run("sparse_export_does_not_materialize_host_disk", ["/bin/sh", "-c",
            "echo PROBE_EXECUTED; truncate -s 1099511627776 /workspace/large-sparse"],
            ["--workspace-mode", "tmpfs", "--disk-bytes", "4194304", "--export", str(sparse_export)],
            expected=125, status="setup_error", check=lambda d, p: not (sparse_export / "large-sparse").exists())
        run("aggregate_limits_require_delegation", ["/bin/true"], ["--memory-bytes", "33554432"],
            expected=125, status="setup_error", started=False)
        # Pause the cleanup guardian while cancelling: the caller must never hang.
        report = root / "guardian-stop.json"
        proc = subprocess.Popen([binary, "run", "--workspace", str(workspace), "--timeout", "3",
                                 "--result", str(report), "--", "/bin/sh", "-c",
                                 "echo PROBE_EXECUTED; sleep 20"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        marker = proc.stdout.readline()
        children = Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
        guard = next((int(p) for p in children if Path(f"/proc/{p}/comm").read_text().strip() == "enclio-guard"), None)
        if guard:
            os.kill(guard, signal.SIGSTOP)
        proc.send_signal(signal.SIGTERM)
        try:
            out, err = proc.communicate(timeout=6)
            data = json.loads(report.read_text()) if report.exists() and report.stat().st_size else {}
            record("stopped_guardian_cannot_hang_cleanup", bool(guard) and b"PROBE_EXECUTED" in marker and proc.returncode != 0,
                   returncode=proc.returncode, stdout=(marker + out).decode(errors="replace"), stderr=err.decode(errors="replace"), result=data)
        except subprocess.TimeoutExpired:
            if guard: os.kill(guard, signal.SIGKILL)
            proc.kill(); proc.communicate(timeout=5)
            record("stopped_guardian_cannot_hang_cleanup", False, error="cleanup exceeded six-second deadline")
        # Never wait on a blocked output consumer to honor cancellation.
        report = root / "slow-output.json"
        proc = subprocess.Popen([binary, "run", "--workspace", str(workspace), "--timeout", "5",
                                 "--output-bytes", "16777216", "--result", str(report), "--",
                                 "/bin/sh", "-c", "echo PROBE_EXECUTED; yes output"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        marker = proc.stdout.readline()
        time.sleep(0.1)
        begin = time.monotonic(); proc.send_signal(signal.SIGTERM)
        stdout, stderr = proc.communicate(timeout=4)
        data = json.loads(report.read_text())
        record("slow_output_consumer_cancellation", b"PROBE_EXECUTED" in marker and
               proc.returncode == 143 and data.get("status") == "cancelled" and
               data.get("cleanup_complete") is True and time.monotonic()-begin < 3,
               returncode=proc.returncode, result=data)
        subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                        "tests/guardian_delay.c", "-ldl", "-o", str(root / "guardian-delay.so")], check=True)
        before = set(Path("/tmp").glob("enclio-??????"))
        report = root / "startup-delay.json"
        env = os.environ.copy(); env["LD_PRELOAD"] = str(root / "guardian-delay.so")
        proc = subprocess.run([binary, "run", "--workspace", str(workspace), "--timeout", "1",
                               "--result", str(report), "--", "/bin/true"],
                              env=env, capture_output=True, timeout=8)
        data = json.loads(report.read_text()) if report.exists() and report.stat().st_size else {}
        residual = set(Path("/tmp").glob("enclio-??????")) - before
        record("guardian_readiness_timeout_cleans_unreported_allocations", proc.returncode != 0 and
               not data.get("command_started") and not residual,
               returncode=proc.returncode, result=data, residual=[str(p) for p in residual],
               stderr=proc.stderr.decode(errors="replace"))
        writable_input = root / "host-stdin"
        writable_input.write_bytes(b"HOST_INPUT_UNCHANGED")
        report = root / "stdin-direction.json"
        with writable_input.open("r+b") as source:
            proc = subprocess.run([binary, "run", "--workspace", str(workspace), "--result", str(report),
                                   "--", "/workspace/probe", "stdin-write"],
                                  stdin=source, capture_output=True, timeout=10)
        data = json.loads(report.read_text())
        record("stdin_does_not_inherit_host_write_capability", proc.returncode == 0 and
               b"PROBE_EXECUTED" in proc.stdout and writable_input.read_bytes() == b"HOST_INPUT_UNCHANGED" and
               data.get("cleanup_complete") is True, stdout=proc.stdout.decode(errors="replace"), result=data)
        report = root / "stdin-eof.json"
        payload = bytes(range(256))*4096
        proc = subprocess.run([binary, "run", "--workspace", str(workspace), "--result", str(report),
                               "--", "/bin/sh", "-c", "echo PROBE_EXECUTED; cat"],
                              input=payload, capture_output=True, timeout=10)
        data = json.loads(report.read_text())
        record("stdin_large_stream_and_eof", proc.returncode == 0 and
               proc.stdout == b"PROBE_EXECUTED\n" + payload and data.get("cleanup_complete") is True,
               input_bytes=len(payload), result=data)
        report = root / "stdin-slow.json"
        proc = subprocess.Popen([binary, "run", "--workspace", str(workspace), "--timeout", "5",
                                 "--result", str(report), "--", "/bin/sh", "-c",
                                 "echo PROBE_EXECUTED; cat"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        marker = proc.stdout.readline(); proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=5)
        data = json.loads(report.read_text())
        record("slow_input_can_be_cancelled", b"PROBE_EXECUTED" in marker and
               proc.returncode == 143 and data.get("status") == "cancelled" and
               data.get("cleanup_complete") is True, result=data)
        run("hugetlb_memory_quota_bypass_denied", ["/workspace/probe", "hugetlb"])
        report = root / "thread-caller.json"
        launch = (
            "import subprocess,threading,sys,json\n"
            "state={}\n"
            "def worker():\n"
            "    p=subprocess.Popen(json.loads(sys.argv[1]),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)\n"
            "    state['p']=p\n"
            "    state['marker']=p.stdout.readline()\n"
            "t=threading.Thread(target=worker); t.start(); t.join()\n"
            "p=state['p']; out,err=p.communicate(timeout=8)\n"
            "print(json.dumps(dict(code=p.returncode,stdout=state['marker']+out,stderr=err)))\n")
        argv = [binary, "run", "--workspace", str(workspace), "--result", str(report), "--",
                "/bin/sh", "-c", "echo PROBE_EXECUTED; sleep 0.5; echo WORKER_THREAD_EXIT_WAS_SAFE"]
        launched = subprocess.run(["python3", "-c", launch, json.dumps(argv)], capture_output=True, text=True, timeout=12)
        observed = json.loads(launched.stdout) if launched.returncode == 0 else {}
        data = json.loads(report.read_text()) if report.exists() and report.stat().st_size else {}
        record("caller_worker_thread_exit_does_not_cancel_process_job", observed.get("code") == 0 and
               "PROBE_EXECUTED" in observed.get("stdout", "") and
               "WORKER_THREAD_EXIT_WAS_SAFE" in observed.get("stdout", "") and
               data.get("status") == "exited" and data.get("cleanup_complete") is True,
               observed=observed, result=data, launcher_stderr=launched.stderr)
        report = root / "guardian-idle.json"
        proc = subprocess.Popen([binary, "run", "--workspace", str(workspace), "--timeout", "4",
                                 "--result", str(report), "--", "/bin/sh", "-c",
                                 "echo PROBE_EXECUTED; sleep 1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        marker = proc.stdout.readline()
        children = Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
        guard = next((int(p) for p in children if Path(f"/proc/{p}/comm").read_text().strip() == "enclio-guard"), None)
        def ticks(pid):
            fields = Path(f"/proc/{pid}/stat").read_text().split()
            return int(fields[13]) + int(fields[14])
        initial_ticks = ticks(guard) if guard else -1
        time.sleep(0.5)
        idle_ticks = ticks(guard)-initial_ticks if guard else -1
        stdout, stderr = proc.communicate(timeout=6)
        data = json.loads(report.read_text())
        record("guardian_idle_has_no_pidfd_busy_loop", bool(guard) and b"PROBE_EXECUTED" in marker and
               0 <= idle_ticks <= 2 and proc.returncode == 0 and data.get("cleanup_complete") is True,
               cpu_ticks_half_second=idle_ticks, result=data)
        if args.cgroup_parent:
            group = ["--cgroup-parent", args.cgroup_parent]
            run("cgroup_memory_oom", ["/workspace/probe", "memory"], group + ["--memory-bytes", "33554432"],
                expected=126, status="resource_limit", reason="memory",
                check=lambda d, p: d.get("resources", {}).get("oom_kills", 0) > 0)
            run("cgroup_pids_aggregate", ["/workspace/probe", "pids"], group + ["--pids-max", "16"],
                expected=126, status="resource_limit", reason="pids",
                check=lambda d, p: d.get("resources", {}).get("pids_max_events", 0) > 0)
            run("cgroup_cpu_bandwidth", ["/workspace/probe", "cpu"], group + ["--cpu-percent", "25", "--timeout", "2"],
                expected=124, status="timeout",
                check=lambda d, p: d.get("resources", {}).get("cpu_throttled_usec", 0) > 0)
            run("cgroup_too_small_for_initialization", ["/bin/true"], group + ["--memory-bytes", "4096"],
                expected=126, status="resource_limit", reason="memory", started=False)
            record("cgroup_children_removed", not any(Path(args.cgroup_parent).glob("enclio-*")))
        identity = json.loads(subprocess.check_output(["python3", "scripts/source-id.py", "--json"], text=True))
        output = dict(schema_version=1, **identity, binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                      aggregate_cases_requested=bool(args.cgroup_parent), results=results,
                      failed=sum(r["status"] != "PASS" for r in results))
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(output, indent=2) + "\n")
        return int(bool(output["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
