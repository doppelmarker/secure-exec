# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this project is

**secure-exec** is an MVP sandbox for executing untrusted Python code, built
around [nsjail](https://github.com/google/nsjail). The design philosophy is
drawn from Liz Rice's *Container Security*: lean on Linux kernel isolation
primitives (namespaces, capabilities, seccomp, cgroups/rlimits, pivot_root)
rather than trusting the application layer.

It is inspired by Windmill's `run.python3.config.proto` but deliberately
**stricter**: where Windmill optimizes for broad compatibility, we enable only
what is needed to run **numpy** and **pandas**, and nothing more.

Core requirement: **the sandbox must run numpy/pandas workloads** while
preventing network access, filesystem escape, privilege escalation, dangerous
syscalls, and resource exhaustion — and we have **tests that prove it**.

## Layout

```
Dockerfile                          multi-stage; builds nsjail, minimal runtime
nsjail/python.proto.template        the nsjail policy (the heart of the sandbox)
sandbox/run.sh                      entrypoint: stage job, render config, exec nsjail
sandbox/runner.py                   in-jail PID-1 runner; reports JSON result on fd 3
apparmor/secure-exec-userns         scoped AppArmor profile granting `userns,`
examples/numpy_pandas.py            sample legitimate workload
tests/conftest.py                   pytest harness that runs snippets via the image
tests/test_functionality.py        positive tests (numpy/pandas etc. still work)
tests/test_security.py             boundary tests (each maps to an isolation layer)
Makefile                            build / run / example / test shortcuts
```

## Security model (defense in depth)

Layers enforced by `nsjail/python.proto.template`:

| Layer | Mechanism | Proven by |
|-------|-----------|-----------|
| Network | `clone_newnet` + `iface_no_lo` (no lo) | `test_no_outbound_tcp`, `test_no_dns`, `test_no_loopback` |
| Filesystem | mount ns + pivot_root, RO minimal binds, tmpfs `/tmp` | `test_host_root_not_visible`, `test_cannot_write_outside_tmp`, `test_sandbox_code_is_readonly` |
| Privilege | `clone_newuser` (rootless: inside-0→outside-unprivileged), `keep_caps:false`, NO_NEW_PRIVS | `test_namespaced_root_only`, `test_no_effective_capabilities`, `test_sensitive_host_files_unreadable` |
| Process | `clone_newpid` (job is PID 1; host table hidden) | `test_host_process_table_hidden` |
| `/proc` leak | fresh namespaced RO procfs; no caps + kernel hardening neuter sensitive files | `test_sensitive_proc_files_leak_nothing` |
| Syscalls | seccomp-bpf KILL list (ptrace, mount, unshare, bpf, …) | `test_ptrace_killed`, `test_unshare_killed` |
| Resources | `rlimit_as/cpu/nproc/fsize/nofile` (all `*_type:VALUE`), `time_limit` | `test_memory_limit`, `test_cpu_time_limit`, `test_fork_bomb_contained` |

We use **modern primitives**: pivot_root (not chroot), user namespaces for
rootless isolation, seccomp-bpf, and PID/IPC/UTS/cgroup namespaces.

## Conventions for changes

- **Minimize what enters the jail.** Every host bind mount must be justified.
  Do **not** copy reference configs' broad binds (e.g. `/etc/passwd`,
  `/etc/resolv.conf`) unless a concrete need is shown. Default to deny.
- **Strict by default; relax only with a test.** If you must open something up
  (new mount, syscall, capability) to support a library, add a positive test
  showing the library works AND confirm the relevant boundary test still passes.
- **The seccomp policy is `DEFAULT ALLOW` with a KILL list.** A pure allow-list
  is too brittle for CPython+numpy; tighten the KILL list rather than flipping
  to allow-list unless you're prepared to maintain it across kernels.
- **The KILL list is arch-parametrized.** kafel only defines some syscall
  identifiers on some arches (an undefined name makes nsjail refuse to start).
  The template carries an arch-independent core + a `{SECCOMP_ARCH_EXTRA}`
  placeholder that `run.sh` fills per `uname -m`. To add a syscall, first probe
  whether it compiles on each arch (run nsjail with a one-line policy and grep
  stderr for "Undefined identifier"), then put it in the core or the right
  arch branch — never add an unprobed name to the core.
- Keep the runtime image free of build tools and package managers (multi-stage).
- The container runs as a non-root user; nsjail builds the inner userns from
  there. Do not add `USER root` or `--privileged`. The userns gate is handled
  by the scoped AppArmor profile (`make apparmor`), not by privilege — see
  "Why these run flags".
- **rlimits need `*_type: VALUE`.** When adding an `rlimit_*`, also pin its
  `rlimit_*_type` to `VALUE` (esp. `rlimit_nproc`, whose type defaults to
  `SOFT`), or nsjail silently ignores the value.

## Build / run / test

This project is managed by **uv** (`.venv` is created by uv; `pytest` lives in
the `dev` dependency group). Tests run via `uv run`, which syncs deps first.

```sh
make build          # docker build -t secure-exec:latest .
make apparmor       # load the AppArmor profile into the host kernel (one-time)
make example        # run examples/numpy_pandas.py through the sandbox
echo 'print(1+1)' | make run
make test           # build + uv run pytest (runs real containers)

# directly, without make:
uv run pytest tests/ -v
```

## Why these run flags

The container runs **non-root, with NO `--privileged` and NO added
capabilities**. The untrusted code inside the jail runs with zero capabilities,
no network, pivot_root'd, seccomp-filtered. The full invocation
(`make run`/`make example` use this; `Makefile` `DOCKER_RUN_FLAGS` and
`tests/conftest.py` mirror it):

```sh
docker run --rm -i --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --pids-limit 256 \
  --memory 1g --memory-swap 1g --cpus 2 \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=secure-exec-userns \
  --security-opt systempaths=unconfined \
  secure-exec:latest - < script.py
```

The flags fall into two groups.

**Outer-container hardening** — we assume the jail *can* be escaped, so the
container is the next wall. (`amicontained` confirmed these take effect: the
default 14-cap bounding set becomes empty, etc.)

- `--cap-drop ALL` — empties the capability bounding set. nsjail's rootless
  userns grants the namespaced caps it needs internally, so the container itself
  needs none. An escapee that reaches euid 0 in the container still has nothing.
- `no-new-privileges` — blocks setuid/fscaps escalation in the container.
- `--read-only` + `--tmpfs /tmp` — immutable rootfs; nsjail writes only under
  `/tmp` (job dir + rendered config), which the tmpfs covers.
- `--pids-limit 256` — outer fork-bomb ceiling at the cgroup level, complementing
  the inner `rlimit_nproc` (which only bounds the inner uid).
- `--memory/--memory-swap/--cpus` — outer resource ceiling so a breakout can't
  exhaust the host even if it defeats the inner rlimits.

**nsjail enablement** — the least privilege needed to *build* the rootless jail:

- `seccomp=unconfined` — disables Docker's *outer* seccomp so nsjail can apply
  its *own* (stricter) policy. Inner code is still seccomp-confined by nsjail.
- `apparmor=secure-exec-userns` — a **scoped** AppArmor profile
  (`apparmor/secure-exec-userns`) that grants only the `userns,` permission.
  Needed because hosts with `kernel.apparmor_restrict_unprivileged_userns=1`
  (Ubuntu 23.10+/6.8, incl. Colima's VM) block *unprivileged + unconfined*
  processes from creating user namespaces. We keep that hardening ON globally
  and whitelist only this container. (`apparmor=unconfined` does NOT work — for
  this kernel gate, "unconfined" is the blocked case; you need a profile that
  allows `userns,`.) Load it with `make apparmor`.
- `systempaths=unconfined` — unmasks `/proc` so nsjail can mount a fresh procfs
  in its PID namespace (Docker's default `/proc` overmounts otherwise make the
  mount fail with "procfs can only be mounted if the original /proc doesn't
  have any other file-systems mounted on top").

This is strictly less than the `--privileged` that nsjail's own Docker examples
(and Windmill's default) use. See the "Gotchas" section for the full diagnosis.

## Target environment

Developed and tested inside **Colima** (macOS Virtualization.Framework, `vz`
with Rosetta) on a **MacBook Pro M4 Pro** (aarch64). The Colima VM runs an
Ubuntu 6.8 kernel which permits unprivileged user namespaces only via the
AppArmor profile above. The config has arm64 library paths
(`/lib/aarch64-linux-gnu`) marked `mandatory:false` so it stays portable to
x86_64. In production (e.g. EKS) the userns gate is a node-level concern; the
image itself needs no privilege.

## Tuning knobs (env vars on the container)

- `SE_TIME_LIMIT` — wall-clock & CPU seconds (default 10)
- `SE_MEM_MB` — address-space cap in MB (default 512)

## Gotchas

- **`mount('/','/',MS_PRIVATE): Permission denied` / `setgroups: Permission
  denied` at startup** = the host is blocking unprivileged userns creation via
  `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu 6.8 / Colima
  default). Fix: `make apparmor` to load the scoped `userns,` profile, then run
  with `--security-opt apparmor=secure-exec-userns`. Do NOT use
  `apparmor=unconfined` — for this kernel gate, unconfined is the *blocked*
  case. Re-run `make apparmor` after a Colima restart (it isn't persisted).
- **`Couldn't mount '/proc'` ("procfs can only be mounted if the original
  /proc doesn't have any other file-systems mounted on top")** = Docker's
  default `/proc` masking. Fix: `--security-opt systempaths=unconfined`.
- **rlimits silently not applied**: each `rlimit_*` needs `rlimit_*_type:
  VALUE`. `rlimit_nproc_type` defaults to `SOFT`, so `rlimit_nproc` was ignored
  until set to `VALUE` — which is why a fork bomb ran to the timeout. All
  `*_type` are now pinned to `VALUE` in the template.
- **cgroup pids limiting is unavailable here**: nsjail's `cgroup_pids_max`
  needs root or `--cgroupns=host` + a delegated cgroup. Our unprivileged
  container can't use it, so fork-bomb defense rests on `rlimit_nproc` +
  `time_limit`, not cgroups.
- **`/proc/1` is the job itself** (PID namespace), so reading `/proc/1/environ`
  returns the job's own env — not a host leak. Tests assert the host process
  table is hidden, not that `/proc/1` is unreadable.
- The structured result is JSON on **fd 3** (so it never collides with the
  user program's stdout). `run.sh` redirects fd 3 to stdout; the test harness
  parses the last JSON line.
- The `/lib64` mount warning on arm64 is harmless (`mandatory:false`; arm64 has
  no `/lib64`). It's kept for x86_64 portability.
- nsjail version is pinned via `NSJAIL_VERSION` build arg.
```