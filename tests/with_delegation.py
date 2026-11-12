#!/usr/bin/env python3
"""Prepare only this process's already-delegated transient service cgroup.

Administrator/systemd creates the Delegate=yes service and its outer limits.
This ordinary-user helper moves itself to a control leaf, enables controllers
on its OWN service group, and execs the requested test command. No host ancestor
or global kernel/LSM setting is changed.
"""
import argparse
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("specify the test command after --")
    if os.getuid() == 0:
        parser.error("run as the ordinary User= of a Delegate=yes transient service")
    relative = next(line.split(":", 2)[2] for line in Path("/proc/self/cgroup").read_text().splitlines()
                    if line.startswith("0::"))
    if relative == "/" or ".." in Path(relative).parts:
        parser.error("refusing a global or out-of-namespace cgroup root")
    parent = Path("/sys/fs/cgroup") / relative.lstrip("/")
    if parent.stat().st_uid != os.getuid():
        parser.error("current service cgroup is not delegated to this user")
    controllers = set((parent / "cgroup.controllers").read_text().split())
    required = {"cpu", "memory", "pids"}
    if not required <= controllers:
        parser.error("delegated service lacks cpu/memory/pids controllers")
    control = parent / "control"
    control.mkdir(mode=0o700, exist_ok=True)
    (control / "cgroup.procs").write_text(str(os.getpid()))
    (parent / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    if not required <= set((parent / "cgroup.subtree_control").read_text().split()):
        parser.error("controller activation readback failed")
    environment = os.environ.copy()
    environment["ENCLIO_CGROUP_PARENT"] = str(parent)
    print("delegated_test_parent=" + str(parent), flush=True)
    os.execvpe(command[0], command, environment)


if __name__ == "__main__":
    main()
