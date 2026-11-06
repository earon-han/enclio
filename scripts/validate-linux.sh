#!/bin/sh
# Use in a Linux VM or an explicitly configured Docker container.
set -eu
cd "$(dirname "$0")/.."
mkdir -p build
{
  uname -a
  cat /etc/os-release
  id
  bwrap --version
  cc --version | head -1
  pkg-config --modversion libseccomp
  cat /proc/self/attr/current 2>/dev/null || true
  sysctl kernel.unprivileged_userns_clone user.max_user_namespaces kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || true
} > build/environment.txt
make
make unit
python3 tests/integration.py --network --output build/integration.json
