# tegum contributor instructions

Read `实施计划.txt`, `docs/design.md` and `docs/tasks.md` before changing behavior.
Implementation is Linux C11; build with `make` and run `make test` as a non-root
user in a supported Linux VM. Keep security boundaries fail closed. Do not turn
a failed sandbox startup into a passing negative test: require execution markers.
Network policy is exact DNS hostname + port 443 CONNECT, with public-address
validation; no implicit direct-network fallback. Changes to these contracts need
an independent review and updated documentation/tests. Keep proxy, execution,
security review, and validation responsibilities separate when using agents.
Record actual VM and Docker results; never claim unexecuted architecture coverage.
Use small task-ID commits. Do not disable host security policies or use privileged
Docker as a substitute for supported container policy.
