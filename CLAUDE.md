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
Dockerfile                          multi-stage; runner / installer / proxy targets
nsjail/python.proto.template        runner (exec) policy — the heart of the sandbox
nsjail/install.proto.template       installer policy — network on, /venv RW
sandbox/run.sh                      runner entrypoint: stage job, render config, exec nsjail
sandbox/runner.py                   in-jail PID-1 runner; reports JSON result on fd 3
sandbox/install.sh                  installer entrypoint: stage driver, render, exec nsjail
sandbox/installer.py                in-jail PID-1 that runs pip; JSON result on fd 3
sandbox/seccomp-arch.sh             per-arch seccomp KILL-list helper (sourced by both)
proxy/tinyproxy.conf, proxy/allowlist   egress proxy: allow pypi.org + files.pythonhosted.org
apparmor/secure-exec-userns         scoped AppArmor profile granting `userns,`
examples/numpy_pandas.py            sample legitimate workload
tests/conftest.py                   pytest harness (runner + installer fixtures)
tests/test_functionality.py        positive tests (numpy/pandas etc. still work)
tests/test_security.py             boundary tests (each maps to an isolation layer)
tests/test_installer.py             install-phase tests (marked `installer`)
Makefile                            build / run / example / test / venv shortcuts
```

## Two-phase model: runner + installer

Users keep a **personal venv** (their chosen PyPI packages) in a per-user volume
and run code against it. Installing arbitrary packages is **arbitrary code
execution and needs network**; running user code must stay **air-gapped**. These
are two trust profiles, so they are two separate images, each with its own nsjail
policy:

| Phase | Image | Network | `/venv` | Limits | Entry |
|-------|-------|---------|---------|--------|-------|
| exec | `secure-exec-runner` | none | read-only | strict (10s/512MB) | `run.sh` |
| install | `secure-exec-installer` | proxy only | read-write | relaxed (300s/2048MB) | `install.sh` |

- **One venv, always.** The runner imports third-party packages only from a
  single venv mounted at `/venv` (`PYTHONPATH=/venv/site`). `run.sh` binds the
  user's volume when one is attached (a populated `/venv/site`), else the
  **default venv** (numpy + pandas) baked into the runner image at
  `/opt/default-venv`. A user venv **fully replaces** the default (not layered).
- **`pip --target`, not `python -m venv`.** The volume holds packages only; the
  executing interpreter is always the trusted image python, never a user-writable
  binary.
- **Egress is enforced at the network layer, not by env vars.** The installer
  joins an `--internal` Docker network whose only peer is the proxy, so it has no
  route to the internet — even raw sockets reach nothing but the proxy. The proxy
  alone bridges out and allow-lists `pypi.org` + `files.pythonhosted.org` (L7).
  `HTTP(S)_PROXY` is set for pip's *functionality*; the *security* is the
  topology. Maps to K8s NetworkPolicy (installer→proxy; proxy→PyPI; runner
  default-deny).
- **Wheel vs source.** Default `SE_INSTALL_MODE=wheel` (`pip --only-binary :all:`)
  ships no compiler and runs no `setup.py` at install time — all package code is
  deferred to import, i.e. to the locked-down runner. `source` mode
  (`installer-source` image) adds gcc/headers to build sdists; that build code
  runs inside the install jail. Wheel is the default; source is opt-in.

Usage:
```sh
make proxy-up                                   # start the egress proxy
make venv-create  USER=alice
make install-venv USER=alice PKGS="rich httpx"  # pip under nsjail, via proxy
echo 'import rich; print(rich.__version__)' | make exec-venv USER=alice
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

Install-phase layers (`nsjail/install.proto.template` + the proxy topology):

| Layer | Mechanism | Proven by |
|-------|-----------|-----------|
| Egress (L3) | `--internal` net: installer's only route is the proxy | `test_install_from_non_pypi_index_is_blocked` |
| Egress (L7) | tinyproxy `FilterDefaultDeny` allow-lists pypi.org + files.pythonhosted.org | `test_install_from_non_pypi_index_is_blocked` |
| venv RO at exec | runner binds `/venv` read-only | `test_venv_readonly_in_exec` |
| no compiler (wheel) | `--only-binary :all:`; image has no gcc | `test_wheel_image_has_no_compiler`, `test_wheel_mode_rejects_sdist_only` |
| install jailed | same caps/seccomp/pivot_root as runner | (install runs under nsjail) |

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

Runner (exec):
- `SE_TIME_LIMIT` — wall-clock & CPU seconds (default 10)
- `SE_MEM_MB` — address-space cap in MB (default 512)

Installer:
- `SE_INSTALL_TIME_LIMIT` — wall/CPU seconds (default 300)
- `SE_INSTALL_MEM_MB` — address-space cap in MB (default 2048)
- `SE_INSTALL_MODE` — `wheel` (default) | `source`
- `SE_PROXY_URL` — egress proxy URL (functional only; topology enforces egress)
- `SE_INDEX_URL` — override pip's index (test hook; a non-PyPI value is blocked
  by the proxy)
- `SE_PIP_TIMEOUT` — pip per-attempt socket timeout, seconds (default 15)
- `SE_PIP_RETRIES` — pip retry count (default 2); bounds how long a blocked or
  flaky index hangs before failing

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
- **The `--internal` proxy network is the load-bearing egress control.** If
  `se-proxy-net` is created WITHOUT `--internal`, Docker's default NAT gives the
  installer direct internet access and the egress guarantee collapses. `make
  proxy-up` always creates it `--internal`.
- **`HTTP(S)_PROXY` is NOT a security boundary** — it's advisory and only makes a
  cooperating pip succeed. Malicious install code that ignores it just finds no
  route (the topology blocks it). Don't "rely on" the env var for isolation.
- **The 1GB per-user venv cap is not enforced locally.** A persistent, *shared*
  volume is needed (installer writes, runner reads), and the stock `local` driver
  has no on-disk quota; a tmpfs volume that DOES cap size is per-container and
  isn't shared. So `make venv-create` uses a plain named volume; the cap is a
  deployment concern (in K8s, the PVC size).
- **New volume is root-owned → install EACCES on `/venv/site`.** Docker copies
  the image's mount-point ownership onto a fresh empty volume, so the installer
  image pre-creates `/venv` owned by uid 10001; otherwise pip (namespaced root →
  host 10001) can't write.
```