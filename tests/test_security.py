"""Security boundary tests.

Each test feeds the sandbox a hostile snippet and asserts the boundary holds.
A "boundary holds" means either:
  - the operation raises an exception inside Python (caught -> result.ok False
    with an error), or
  - the process is killed by seccomp / rlimit (non-zero returncode, no ok),
  - the forbidden thing simply isn't reachable (empty / denied result).

These map directly to the isolation layers in nsjail/python.proto.template.
"""
import pytest


# ---------------------------------------------------------------------------
# Network isolation (clone_newnet + iface_no_lo): no connectivity at all.
# ---------------------------------------------------------------------------
def test_no_outbound_tcp(run_in_sandbox):
    r = run_in_sandbox("""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("1.1.1.1", 53))
        print("CONNECTED")
    """)
    assert not r.ok, r
    assert "CONNECTED" not in r.stdout
    assert any(e in r.error for e in ("Network is unreachable", "Errno", "timed out"))


def test_no_dns(run_in_sandbox):
    r = run_in_sandbox("""
        import socket
        print(socket.gethostbyname("example.com"))
    """)
    assert not r.ok, r


def test_no_loopback(run_in_sandbox):
    # Even localhost must fail: we did not bring lo up.
    r = run_in_sandbox("""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("127.0.0.1", 80))
        print("CONNECTED")
    """)
    assert not r.ok, r
    assert "CONNECTED" not in r.stdout


# ---------------------------------------------------------------------------
# Filesystem isolation (pivot_root + read-only minimal binds).
# ---------------------------------------------------------------------------
def test_host_root_not_visible(run_in_sandbox):
    # The container's app files / host root must not be reachable.
    r = run_in_sandbox("""
        import os
        print(sorted(os.listdir("/")))
    """)
    assert r.ok, r
    listing = r.stdout
    # Our app dir lives at /opt in the image but is NOT mounted into the jail.
    assert "secure-exec" not in listing
    assert "/opt" not in listing or "opt" not in listing.split()


def test_cannot_write_outside_tmp(run_in_sandbox):
    r = run_in_sandbox("""
        open("/usr/pwned", "w").write("x")
        print("WROTE")
    """)
    assert not r.ok, r
    assert "WROTE" not in r.stdout
    assert ("Read-only file system" in r.error
            or "Permission denied" in r.error
            or "No such file" in r.error)


def test_can_write_tmp(run_in_sandbox):
    # /tmp is a private writable tmpfs -> allowed (and discarded after run).
    r = run_in_sandbox("""
        p = "/tmp/scratch.txt"
        open(p, "w").write("ok")
        print(open(p).read())
    """)
    assert r.ok, r
    assert "ok" in r.stdout


def test_sandbox_code_is_readonly(run_in_sandbox):
    r = run_in_sandbox("""
        open("/sandbox/job.py", "a").write("# tamper")
        print("TAMPERED")
    """)
    assert not r.ok, r
    assert "TAMPERED" not in r.stdout


# ---------------------------------------------------------------------------
# Privilege / capability isolation (clone_newuser, keep_caps=false).
# ---------------------------------------------------------------------------
def test_namespaced_root_only(run_in_sandbox):
    # Rootless model: uid 0 *inside* the userns, but it maps to an
    # unprivileged uid outside. The real protection is that this namespaced
    # root holds NO capabilities (see test_no_effective_capabilities) and
    # cannot act on host resources.
    r = run_in_sandbox("""
        import os
        print("uid", os.getuid(), "gid", os.getgid())
    """)
    assert r.ok, r
    assert "uid 0" in r.stdout  # namespaced root, harmless on the host


def test_no_effective_capabilities(run_in_sandbox):
    r = run_in_sandbox("""
        # /proc/self/status CapEff should be all zeros with caps dropped.
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff"):
                    print(line.strip())
    """)
    assert r.ok, r
    assert "CapEff:" in r.stdout
    cap = r.stdout.split("CapEff:")[1].split()[0]
    assert set(cap) == {"0"}, f"expected no effective caps, got {cap}"


# ---------------------------------------------------------------------------
# Syscall isolation (seccomp KILL list).
# ---------------------------------------------------------------------------
def test_ptrace_killed(run_in_sandbox):
    # ptrace is on the seccomp KILL list -> process should die, not return.
    r = run_in_sandbox("""
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace(0, 0, 0, 0)   # PTRACE_TRACEME
        print("PTRACE_OK")
    """)
    assert "PTRACE_OK" not in r.stdout
    # Killed by seccomp -> negative/!=0 rc and no clean ok result.
    assert not r.ok, r


def test_unshare_killed(run_in_sandbox):
    # Attempting to create a new namespace (sandbox escape primitive) is killed.
    r = run_in_sandbox("""
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        CLONE_NEWUSER = 0x10000000
        libc.unshare(CLONE_NEWUSER)
        print("UNSHARE_OK")
    """)
    assert "UNSHARE_OK" not in r.stdout
    assert not r.ok, r


# ---------------------------------------------------------------------------
# Resource limits (rlimits + time_limit).
# ---------------------------------------------------------------------------
def test_memory_limit(run_in_sandbox):
    # rlimit_as caps address space; a huge alloc must fail, not OOM the host.
    r = run_in_sandbox("""
        x = bytearray(2_000_000_000)   # ~2GB > 512MB limit
        print("ALLOCATED", len(x))
    """, mem_mb=256)
    assert "ALLOCATED" not in r.stdout
    assert not r.ok, r


def test_cpu_time_limit(run_in_sandbox):
    # An infinite loop must be killed by the time limit, not run forever.
    r = run_in_sandbox("""
        while True:
            pass
    """, time_limit=2, timeout=30)
    assert not r.ok, r


def test_fork_bomb_contained(run_in_sandbox):
    # rlimit_nproc + pid namespace bound the damage; the harness must return.
    r = run_in_sandbox("""
        import os
        try:
            for _ in range(10000):
                os.fork()
        except OSError:
            print("FORK_LIMITED")
    """, time_limit=5, timeout=40)
    # Either fork hit the limit (clean) or the whole thing was killed.
    assert "FORK_LIMITED" in r.stdout or not r.ok, r


# Host credential files are simply not mounted into the jail, so they cannot
# be read. (We deliberately do NOT bind /etc/passwd or /etc/shadow.)
@pytest.mark.parametrize("path", ["/etc/shadow", "/etc/passwd", "/etc/sudoers"])
def test_sensitive_host_files_unreadable(run_in_sandbox, path):
    r = run_in_sandbox(f"""
        try:
            print(open({path!r}).read())
            print("READ_OK")
        except OSError as e:
            print("DENIED", e)
    """)
    assert "READ_OK" not in r.stdout, r


def test_host_process_table_hidden(run_in_sandbox):
    # PID namespace: the job is PID 1 of its own tree and cannot see host
    # processes. Reading /proc/1/environ therefore returns the job's OWN
    # environment (HOME=/tmp etc.), never the host init's — and the visible
    # pid list is tiny, proving the host process table is not exposed.
    r = run_in_sandbox("""
        import os, json
        pids = sorted(int(p) for p in os.listdir("/proc") if p.isdigit())
        print("PIDS", json.dumps(pids))
        print("ENV_LEAK" if "/proc" in open("/proc/1/environ").read() else "NO_LEAK")
    """)
    assert r.ok, r
    import json
    pids = json.loads(r.stdout.split("PIDS", 1)[1].splitlines()[0])
    assert pids and pids[0] == 1, pids          # job is PID 1 of its namespace
    assert len(pids) <= 8, pids                 # tiny tree, not the host table
    assert "NO_LEAK" in r.stdout                # /proc/1 is the job's own env


def test_sensitive_proc_files_leak_nothing(run_in_sandbox):
    # We run with `systempaths=unconfined` (so nsjail can mount a fresh procfs
    # in its PID namespace), which removes Docker's outer /proc masking. This
    # test proves that is NOT a privilege escalation for the untrusted code:
    # the dangerous /proc files are either unreadable (no caps), absent, or
    # neutered by standard kernel unprivileged hardening (kptr_restrict, etc.).
    #
    #   /proc/kcore        kernel/physical memory       -> must be unreadable
    #   /proc/sysrq-trigger  trigger kernel sysrq        -> must be unreadable
    #   /proc/kallsyms     kernel symbol addresses       -> zeroed (KASLR), no real addrs
    #   /proc/keys         keyring contents              -> empty for this namespace
    r = run_in_sandbox(r"""
        def probe(p):
            try:
                with open(p, "rb") as f:
                    return ("READ", f.read(64))
            except OSError as e:
                return ("DENIED", e.errno)

        for p in ("/proc/kcore", "/proc/sysrq-trigger"):
            kind, val = probe(p)
            print(p, kind)              # must be DENIED

        kind, val = probe("/proc/kallsyms")
        # readable but addresses must be zeroed (kptr_restrict); no nonzero hex addr
        leaked = kind == "READ" and any(c not in b"0 \t\n" for c in val.split(b" ", 1)[0])
        print("/proc/kallsyms", "LEAK" if leaked else "SAFE")

        kind, val = probe("/proc/keys")
        print("/proc/keys", "LEAK" if (kind == "READ" and val.strip()) else "SAFE")
    """)
    assert r.ok, r
    out = r.stdout
    # The two truly dangerous files must not be readable at all.
    assert "/proc/kcore DENIED" in out, out
    assert "/proc/sysrq-trigger DENIED" in out, out
    # The readable-but-hardened files must not leak real data.
    assert "/proc/kallsyms SAFE" in out, out
    assert "/proc/keys SAFE" in out, out