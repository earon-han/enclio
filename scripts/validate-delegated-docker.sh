#!/bin/bash
# Explicitly approved disposable-container validation bootstrap.
# Runtime remains UID1000, cap-drop ALL. The administrator only delegates this
# container's OWN cgroup, preserving its outer memory/CPU/PID safety net.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $(id -u) != 0 ]]; then
  echo 'Run the approved test bootstrap as Linux VM administrator (sudo).' >&2
  exit 2
fi
image=${ENCLIO_TEST_IMAGE:-enclio-delegated-validation}
name="enclio-delegated-$$"
action=${ENCLIO_TEST_ACTION:-validation}
if [[ "$action" != validation && "$action" != soak ]]; then
  echo 'ENCLIO_TEST_ACTION must be validation or soak.' >&2; exit 2
fi
evidence="build/delegated-docker/$name"
mkdir -p "$evidence"
printf 'container_name=%s\nevidence=%s\n' "$name" "$evidence"
cleanup() {
  docker inspect "$name" > "$evidence/inspect.json" 2>/dev/null || true
  docker logs "$name" > "$evidence/test.log" 2>&1 || true
  for file in environment.txt integration.json resource-integration.json network-integration.json options-integration.json fuzz.log; do
    docker cp "$name:/opt/enclio/build/$file" "$evidence/$file" 2>/dev/null || true
  done
  if [[ "$action" == soak ]]; then
    docker cp "$name:/opt/enclio/build/soak" "$evidence/soak" 2>/dev/null || true
  fi
  docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
if [[ ${ENCLIO_SKIP_BUILD:-0} != 1 ]]; then
  docker build --build-arg "BASE_IMAGE=${ENCLIO_BASE_IMAGE:-ubuntu:24.04}" -t "$image" .
fi
id=$(docker run -d --name "$name" --user 1000:1000 --cap-drop ALL \
  --memory 768m --memory-swap 768m --cpus 2 --pids-limit 256 \
  --env "ENCLIO_TEST_ACTION=$action" --env "ENCLIO_SOAK_SECONDS=${ENCLIO_SOAK_SECONDS:-86400}" \
  --security-opt "seccomp=$PWD/scripts/docker-seccomp.json" \
  --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
  "$image" /bin/sh -c 'while ! test -e /tmp/enclio-cgroup-ready; do sleep 0.05; done; if test "$ENCLIO_TEST_ACTION" = soak; then exec python3 scripts/soak.py --binary build/enclio --duration "$ENCLIO_SOAK_SECONDS" --cgroup-parent /run/enclio-cgroup --output build/soak; else ENCLIO_CGROUP_PARENT=/run/enclio-cgroup exec scripts/validate-linux.sh; fi')
pid=$(docker inspect --format '{{.State.Pid}}' "$id")
relative=$(awk -F: '$1=="0" {print $3}' "/proc/$pid/cgroup")
parent="/sys/fs/cgroup$relative"
if [[ ! -f "$parent/cgroup.controllers" || "$parent" == /sys/fs/cgroup ]]; then
  echo 'Cannot identify a private container cgroup.' >&2; exit 2
fi
mkdir "$parent/control"
for attempt in {1..20}; do
  while read -r member; do
    [[ -n "$member" ]] && echo "$member" > "$parent/control/cgroup.procs" || true
  done < "$parent/cgroup.procs"
  [[ -z $(cat "$parent/cgroup.procs") ]] && break
  sleep 0.01
done
echo '+cpu +memory +pids' > "$parent/cgroup.subtree_control"
chown 1000:1000 "$parent" "$parent/cgroup.procs" "$parent/cgroup.subtree_control" "$parent/cgroup.threads"
# A fresh cgroup2 mount in the container's PRIVATE cgroup namespace is rooted
# by the kernel at this container's own group, never at a writable host ancestor.
if [[ $(readlink "/proc/$pid/ns/cgroup") == $(readlink /proc/self/ns/cgroup) ]]; then
  echo 'Refusing delegation without a private container cgroup namespace.' >&2; exit 2
fi
nsenter --target "$pid" --mount --pid --cgroup --root -- /bin/mkdir -p /run/enclio-cgroup
nsenter --target "$pid" --mount --pid --cgroup --root -- /bin/mount -t cgroup2 -o rw,nosuid,nodev,noexec none /run/enclio-cgroup
printf 'container_id=%s\ncontainer_cgroup=%s\nouter_memory_bytes=805306368\nouter_cpu_percent=200\nouter_pids_max=256\ndelegated_uid=1000\n' "$id" "$relative" > "$evidence/delegation.txt"
cat "$parent/cgroup.controllers" "$parent/cgroup.subtree_control" >> "$evidence/delegation.txt"
cat "/proc/$pid/mountinfo" > "$evidence/namespace.txt"
# docker exec would re-enter the now-empty parent cgroup and violate the v2
# no-internal-process rule, so signal the existing waiter through its root view.
touch "/proc/$pid/root/tmp/enclio-cgroup-ready"
status=$(docker wait "$name")
exit "$status"
