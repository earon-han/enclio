#!/bin/sh
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
  cat /proc/self/cgroup
  sysctl kernel.unprivileged_userns_clone user.max_user_namespaces kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || true
  if test -n "${ENCLIO_CGROUP_PARENT:-}"; then
    printf 'delegated_test_parent=%s\n' "$ENCLIO_CGROUP_PARENT"
    cat "$ENCLIO_CGROUP_PARENT/cgroup.controllers"
    cat "$ENCLIO_CGROUP_PARENT/cgroup.subtree_control"
  fi
} > build/environment.txt
make
status=0
make unit || status=1
make fuzz-smoke > build/fuzz.log 2>&1 || status=1
python3 tests/integration.py --network --output build/integration.json || status=1
if test -n "${ENCLIO_CGROUP_PARENT:-}"; then
  python3 tests/resource_integration.py --cgroup-parent "$ENCLIO_CGROUP_PARENT" --output build/resource-integration.json || status=1
else
  python3 tests/resource_integration.py --output build/resource-integration.json || status=1
fi
python3 tests/network_integration.py --output build/network-integration.json || status=1
python3 tests/options_integration.py --output build/options-integration.json || status=1
exit "$status"
