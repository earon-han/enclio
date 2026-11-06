# Enclio contributor instructions

Read `实施计划.txt`, `docs/completion-plan.md`, `docs/design.md` and `docs/tasks.md`
before changing behavior. Implementation is Linux C11. `src/enclio.h` and documented
CLI/result fields are public contracts; inspect callers, examples and tests.

Keep security boundaries fail closed. Requested limits must either be enforced
with their documented scope or reject startup. Never substitute a per-process or
per-file rlimit for an aggregate cgroup/filesystem quota. Do not expose writable
cgroup/export/control handles to payloads or move container jobs outside their
outer cgroup. Native strict seccomp is the default; compatibility mode is explicit.

All TCP protocols share exact DNS-host:port authorization and all-address public
validation. HTTP, CONNECT and SOCKS5 domain CONNECT are supported; UDP/QUIC,
SOCKS BIND/UDP ASSOCIATE and TLS decryption are not. Never add production test
switches that allow private-address bypass or a direct-network fallback.

Keep design review, implementation and independent validation responsibilities
separate when using agents. A negative security test must prove its payload ran;
startup denial is BLOCKED, never a passing attack test. Run Linux VM and Docker
separately, record their real security policies, and do not infer architecture or
long-duration coverage from unexecuted tests. Preserve source/binary identities
and raw observations; do not rename old evidence into a claimed new run.

Use `make`, relevant unit/integration targets and the validation scripts as an
ordinary user in supported Linux. Maintain documents for public changes. Do not
change global host security settings or use privileged Docker to hide missing
capabilities. Scoped environment changes still require the task's authorization.
Follow the user's commit/amend contract; do not add commits when amend is required.
Do not claim a preview, test run, external audit or Release has completed before
its acceptance evidence exists.

## Explicit caller policy extensions

See `docs/options-extension-20261111.md` before changing configurable policy.
Default networking remains none; old allow-only calls infer isolated. Isolated
requires valid allow rules. Explicit host mode shares the immediate parent netns
and broadens network access; it is never a direct-network fallback. Reject allow
rules combined with explicit none/host modes.

Extra directory mounts are explicit caller grants. Preserve protected path and
control-filesystem checks, FD-based source binding and workload FD closure. Do
not claim tmpfs disk quotas cover extra writable host mounts; reject rw mounts
combined with disk-bytes.

User syscall actions override the target's default actions and argument filters
for that syscall. Build the effective target filters before loading them; an
inherited deny filter cannot be relaxed by a later allow. Keep trusted init/proxy
policies separate and fixed, and preserve no_new_privs/native-ABI constraints.
Document that explicit caller relaxations change the corresponding default
security guarantees and cannot override an outer seccomp filter.
