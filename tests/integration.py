#!/usr/bin/env python3
"""Linux integration suite. Startup denial is BLOCKED, never a passing attack test."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="build/tegum")
    parser.add_argument("--output", default="build/integration.json")
    parser.add_argument("--network", action="store_true")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    results = []
    samples = []
    before_run_dirs = set(Path("/tmp").glob("tegum-??????"))
    def record(name, status, **detail):
        results.append(dict(name=name, status=status, **detail))
        print(f"{status}: {name}", flush=True)
    with tempfile.TemporaryDirectory(prefix="tegum-tests-") as root:
        root = Path(root)
        workspace = root / "workspace"
        workspace.mkdir()
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-O2", "tests/probe.c", "-o", str(workspace / "probe")], check=True)
        secret = root / "secret"
        secret.write_text("HOST_SECRET")
        (workspace / "escape").symlink_to(secret)
        index = 0
        def command(cmd, options=(), **kwargs):
            nonlocal index
            index += 1
            report = root / f"result-{index}.json"
            return [binary, "run", "--workspace", str(workspace), "--timeout", "5",
                    "--result", str(report), *options, "--", *cmd], report
        def run(name, cmd, options=(), expected=0, marker=True, **kwargs):
            argv, report = command(cmd, options)
            begin = time.monotonic()
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=15, **kwargs)
            elapsed = (time.monotonic() - begin) * 1000
            data = json.loads(report.read_text()) if report.exists() else {}
            detail = dict(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr,
                          result=data, elapsed_ms=round(elapsed, 3))
            if not data.get("command_started") or (marker and "PROBE_EXECUTED" not in proc.stdout):
                record(name, "BLOCKED", **detail)
                return False
            valid = (proc.returncode == expected and data.get("schema_version") == 1 and
                     data.get("status") == ("timeout" if expected == 124 else "exited"))
            if name == "target_signal":
                valid = valid and data.get("signal") == 15
            if name == "business_exit_143":
                valid = valid and data.get("signal") == 0
            record(name, "PASS" if valid else "FAIL", **detail)
            return valid
        argv, report = command(["/bin/true"])
        initial = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        initial_data = json.loads(report.read_text()) if report.exists() else {}
        if initial.returncode != 0 or not initial_data.get("command_started"):
            record("platform_startup", "BLOCKED", returncode=initial.returncode,
                   stdout=initial.stdout, stderr=initial.stderr, result=initial_data)
        else:
            record("platform_startup", "PASS", result=initial_data)
            run("filesystem_and_symlink", ["/workspace/probe", "filesystem", str(secret)])
            if (workspace / "authorized").read_text() != "allowed":
                record("workspace_host_write", "FAIL")
            run("seccomp_and_alternate_syscalls", ["/workspace/probe", "seccomp"])
            env = os.environ.copy()
            env.update(TEGUM_HOST_SECRET="secret", SSH_AUTH_SOCK="/tmp/agent", BASH_ENV="/tmp/hook")
            run("trusted_supervisor_control", ["/workspace/probe", "control"])
            run("environment_allowlist", ["/workspace/probe", "env"],
                ["--env", "EXPLICIT_TEST=hello world"], env=env)
            with secret.open() as fd:
                run("inherited_fds", ["/workspace/probe", "fds"], pass_fds=(fd.fileno(),))
            run("business_nonzero", ["/bin/sh", "-c", "echo PROBE_EXECUTED; exit 23"], expected=23)
            run("target_signal", ["/bin/sh", "-c", "echo PROBE_EXECUTED; kill -TERM $$"], expected=143)
            run("business_exit_143", ["/bin/sh", "-c", "echo PROBE_EXECUTED; exit 143"], expected=143)
            run("stdout_stderr", ["/bin/sh", "-c", "echo PROBE_EXECUTED; echo business-error >&2"])
            run("timeout", ["/bin/sh", "-c", "echo PROBE_EXECUTED; sleep 20"],
                ["--timeout", "1"], expected=124)
            run("background_setsid_cleanup", ["/workspace/probe", "daemon", "/workspace/leaked"])
            time.sleep(1)
            record("background_did_not_survive", "FAIL" if (workspace / "leaked").exists() else "PASS")
            argv, report = command(["/bin/sh", "-c", "echo PROBE_EXECUTED; sleep 20"])
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            line = proc.stdout.readline()
            proc.send_signal(signal.SIGTERM)
            stdout, stderr = proc.communicate(timeout=10)
            data = json.loads(report.read_text()) if report.exists() else {}
            record("cancellation", "PASS" if "PROBE_EXECUTED" in line and
                   proc.returncode == 143 and data.get("status") == "cancelled" else "FAIL",
                   returncode=proc.returncode, stdout=line + stdout, stderr=stderr, result=data)
            # Kill the CLI itself after proving that its detached descendant exists.
            before_dirs = set(Path("/tmp").glob("tegum-??????"))
            argv, report = command(["/workspace/probe", "daemon-hold", "/workspace/caller-leak"])
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            lines = proc.stdout.readline() + proc.stdout.readline()
            proc.kill()
            stdout, stderr = proc.communicate(timeout=10)
            time.sleep(1)
            leftovers = set(Path("/tmp").glob("tegum-??????")) - before_dirs
            record("caller_sigkill_cleanup", "PASS" if "CHILD_SPAWNED" in lines and
                   proc.returncode == -9 and not (workspace / "caller-leak").exists() else "FAIL",
                   stdout=lines + stdout, stderr=stderr,
                   leftover_private_directories=[dict(path=str(p), mode=oct(p.stat().st_mode & 0o777)) for p in leftovers])
            for p in leftovers:
                shutil.rmtree(p)
            argv, report = command(["/workspace/probe", "daemon-hold", "/workspace/deadcaller-leak"])
            observed = root / "caller-observed.json"
            launcher_code = ("import json,os,subprocess,sys; "
                "p=subprocess.Popen(json.loads(sys.argv[1]),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True); "
                "lines=p.stdout.readline()+p.stdout.readline(); "
                "open(sys.argv[2],'w').write(json.dumps(dict(pid=p.pid,lines=lines))); os._exit(0)")
            subprocess.run(["python3", "-c", launcher_code, json.dumps(argv), str(observed)], timeout=10, check=True)
            seen = json.loads(observed.read_text())
            for _ in range(100):
                if report.exists() and report.stat().st_size:
                    break
                time.sleep(0.02)
            time.sleep(1)
            data = json.loads(report.read_text()) if report.exists() and report.stat().st_size else {}
            record("actual_caller_exit", "PASS" if "CHILD_SPAWNED" in seen["lines"] and
                   data.get("status") == "cancelled" and data.get("signal") == 15 and
                   not (workspace / "deadcaller-leak").exists() else "FAIL", result=data)
            argv, report = command(["/bin/true"], ["--cwd", "/workspace/missing-cwd"])
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
            data = json.loads(report.read_text()) if report.exists() else {}
            record("cwd_startup_failure", "PASS" if proc.returncode == 125 and
                   data.get("status") == "setup_error" and not data.get("command_started") else "FAIL",
                   stderr=proc.stderr, result=data)
            # CLI must reject a control/result file that the workload can forge.
            bad_result = subprocess.run([binary, "run", "--workspace", str(workspace),
                "--result", str(workspace / "forged.json"), "--", "/bin/true"], capture_output=True, text=True)
            record("result_outside_workspace", "PASS" if bad_result.returncode == 2 and
                   not (workspace / "forged.json").exists() else "FAIL", stderr=bad_result.stderr)
            preload_c = workspace / "preload.c"
            preload_c.write_text('#include <unistd.h>\n__attribute__((constructor)) static void c(void){(void)!write(1,"PRELOAD_TARGET\\n",15); }\n')
            subprocess.run(["cc", "-shared", "-fPIC", str(preload_c), "-o", str(workspace / "preload.so")], check=True)
            argv, report = command(["/bin/true"], ["--env", "LD_PRELOAD=/workspace/preload.so"])
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
            data = json.loads(report.read_text()) if report.exists() else {}
            record("ld_preload_target_only", "PASS" if proc.returncode == 0 and
                   proc.stdout.count("PRELOAD_TARGET") == 1 and data.get("command_started") else "FAIL",
                   stdout=proc.stdout, stderr=proc.stderr, result=data)
            argv, report = command(["/does-not-exist"])
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
            data = json.loads(report.read_text()) if report.exists() else {}
            record("exec_startup_failure", "PASS" if proc.returncode == 125 and
                   data.get("status") == "setup_error" and not data.get("command_started") else "FAIL",
                   returncode=proc.returncode, stderr=proc.stderr, result=data)
            # A literal address avoids DNS failure masquerading as network isolation.
            direct = "echo PROBE_EXECUTED; curl -k --noproxy '*' --connect-timeout 1 --max-time 2 https://1.1.1.1; test $? -ne 0"
            run("direct_network_denied", ["/bin/sh", "-c", direct])
            if args.network:
                run("trusted_init_and_relay_control", ["/workspace/probe", "control", "network"],
                    ["--allow-host", "example.com"])
                argv, report = command(["/bin/sh", "-c", "echo PROBE_EXECUTED; sleep 20"],
                    ["--allow-host", "example.com"])
                proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                line = proc.stdout.readline()
                children = Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
                proxy_pid = next((int(p) for p in children if
                    Path(f"/proc/{p}/comm").read_text().strip() == "tegum"), None)
                if proxy_pid:
                    os.kill(proxy_pid, signal.SIGKILL)
                stdout, stderr = proc.communicate(timeout=10)
                data = json.loads(report.read_text()) if report.exists() else {}
                record("host_proxy_failure", "PASS" if proxy_pid and "PROBE_EXECUTED" in line and
                       proc.returncode == 125 and data.get("status") == "setup_error" and
                       data.get("command_started") else "FAIL", stderr=stderr, result=data)
                argv, report = command(["/workspace/probe", "relay-fault"], ["--allow-host", "example.com"])
                proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
                data = json.loads(report.read_text()) if report.exists() else {}
                record("relay_failure", "PASS" if "RELAY_KILLED" in proc.stdout and
                       proc.returncode == 125 and data.get("status") == "setup_error" and
                       data.get("command_started") else "FAIL", stdout=proc.stdout, stderr=proc.stderr, result=data)
                run("https_allowlist", ["/bin/sh", "-c", "echo PROBE_EXECUTED; curl -fSs --max-time 10 https://example.com >/tmp/page; test -s /tmp/page"],
                    ["--allow-host", "example.com", "--timeout", "15"])
                run("https_host_denied", ["/bin/sh", "-c", "echo PROBE_EXECUTED; curl -fSs --max-time 3 https://example.org; test $? -ne 0"],
                    ["--allow-host", "example.com"])
                run("proxy_environment_removal_cannot_bypass", ["/bin/sh", "-c", direct],
                    ["--allow-host", "example.com"])
                run("http_unsupported", ["/bin/sh", "-c", "echo PROBE_EXECUTED; curl -fSs --max-time 3 http://example.com; test $? -ne 0"],
                    ["--allow-host", "example.com"])
            for _ in range(100):
                argv, report = command(["/bin/true"])
                begin = time.perf_counter()
                proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
                data = json.loads(report.read_text()) if report.exists() else {}
                samples.append(dict(elapsed_ms=round((time.perf_counter()-begin)*1000, 3),
                                    returncode=proc.returncode, command_started=data.get("command_started", False)))
            record("repeat_100", "PASS" if all(s["returncode"] == 0 and s["command_started"] for s in samples) else "FAIL")
            def parallel(_):
                # Independent reports prevent a concurrent-write test artifact.
                with tempfile.NamedTemporaryFile(dir=root, suffix=".json") as r:
                    proc = subprocess.run([binary, "run", "--workspace", str(workspace), "--result", r.name,
                                           "--", "/bin/true"], capture_output=True, timeout=10)
                    data = json.loads(Path(r.name).read_text())
                    return proc.returncode == 0 and data.get("command_started")
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                passed = list(pool.map(parallel, range(12)))
            record("concurrent_4x3", "PASS" if all(passed) else "FAIL")
    leftover_dirs = set(Path("/tmp").glob("tegum-??????")) - before_run_dirs
    record("normal_temporary_directory_cleanup", "FAIL" if leftover_dirs else "PASS",
           leftover_directories=[str(p) for p in leftover_dirs])
    identity = json.loads(subprocess.check_output(["python3", "scripts/source-id.py", "--json"], text=True))
    output = dict(schema_version=1, **identity, binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                  platform=subprocess.check_output(["uname", "-a"], text=True).strip(),
                  results=results, benchmark_samples=samples,
                  failed=sum(r["status"] == "FAIL" for r in results),
                  blocked=sum(r["status"] == "BLOCKED" for r in results))
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(output, indent=2) + "\n")
    return 1 if output["failed"] else 2 if output["blocked"] else 0

if __name__ == "__main__":
    raise SystemExit(main())
