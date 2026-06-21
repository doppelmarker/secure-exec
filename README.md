# secure-exec

A minimal, strict sandbox for executing untrusted **Python** code with
[nsjail](https://github.com/google/nsjail). Strong enough to run `numpy` /
`pandas`, locked down everywhere else — with a test suite that proves the
boundaries hold.

See [CLAUDE.md](./CLAUDE.md) for the full security model and contributor notes.

## Quick start

```sh
make build                   # builds runner + installer + proxy images
make apparmor                # one-time: load the scoped userns AppArmor profile
make example                 # numpy + pandas workload (default venv)
echo 'print(2**10)' | make run
make test                    # security + functionality + installer suite
```

### Per-user venvs

Users keep a personal venv of PyPI packages and run code against it. Installs run
under nsjail with egress restricted to PyPI via a proxy; exec stays air-gapped.

```sh
make proxy-up                                   # start the egress proxy
make venv-create  USER=alice
make install-venv USER=alice PKGS="rich httpx"  # pip under nsjail, via proxy
echo 'import rich; print(rich.__version__)' | make exec-venv USER=alice
```

See [CLAUDE.md](./CLAUDE.md) → "Two-phase model" for the runner/installer split,
the egress topology, and wheel-vs-source mode.

`make apparmor` loads `apparmor/secure-exec-userns` into the host kernel. It is
needed on hosts that set `kernel.apparmor_restrict_unprivileged_userns=1`
(Ubuntu 23.10+/6.8, including Colima's VM) to let the **non-root, unprivileged**
container create the user namespace nsjail needs — without `--privileged` or
added capabilities. Re-run it after a Colima restart. See
[CLAUDE.md](./CLAUDE.md) → "Why these run flags".

## How it works

`run.sh` stages the submitted script read-only, renders
`nsjail/python.proto.template`, and execs `nsjail`, which:

- enters fresh **user / pid / net / ipc / uts / mount / cgroup** namespaces,
- **pivot_root**s into a minimal, mostly read-only rootfs,
- drops **all capabilities** and sets **no_new_privs**,
- applies a **seccomp** KILL list for escape-prone syscalls,
- enforces **rlimits** and a wall-clock time limit,
- exposes **no network at all** (not even loopback).

The user code is run by `runner.py`, which reports a structured JSON result on
file descriptor 3.

## Requirements

Docker with a kernel that allows unprivileged user namespaces (directly, or via
the bundled AppArmor profile — see `make apparmor`). Developed on Colima
(`vz` + Rosetta) / Apple Silicon; portable to x86_64 Linux. The container runs
**non-root, with `--cap-drop ALL`, no `--privileged`, read-only rootfs, and
pid/memory limits** — plus three scoped `--security-opt` flags that let nsjail
build the rootless jail. The outer-container hardening was driven by an
`amicontained` audit (`make audit`); see CLAUDE.md "Why these run flags".
```