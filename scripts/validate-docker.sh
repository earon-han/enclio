#!/bin/sh
# Opt-in container policy, no added capabilities or privileged mode.
# WARNING: the host operator explicitly relaxes Docker's outer seccomp,
# AppArmor and proc masking. Read docs/dependencies.md before use.
set -eu
cd "$(dirname "$0")/.."
task_name="enclio-validation-$$"
mkdir -p build/docker
docker build -t enclio-validation .
trap 'docker rm -f "$task_name" >/dev/null 2>&1 || true' EXIT INT TERM
status=0
docker run --name "$task_name" --cap-drop ALL \
  --security-opt "seccomp=$PWD/scripts/docker-seccomp.json" \
  --security-opt apparmor=unconfined \
  --security-opt systempaths=unconfined \
  enclio-validation scripts/validate-linux.sh || status=$?
docker cp "$task_name:/opt/enclio/build/integration.json" build/docker/integration.json
docker cp "$task_name:/opt/enclio/build/environment.txt" build/docker/environment.txt
docker inspect "$task_name" > build/docker/inspect.json
exit "$status"
