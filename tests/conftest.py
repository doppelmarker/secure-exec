"""Pytest fixtures: run a Python snippet through the sandbox container.

These tests exercise the *real* nsjail sandbox by invoking the built Docker
image, so they must run on a host with Docker (Colima) available and the image
already built:

    docker build -t secure-exec:latest .

Set SECURE_EXEC_IMAGE to override the image tag.
"""
import json
import os
import shutil
import subprocess
import textwrap

import pytest

IMAGE = os.environ.get("SECURE_EXEC_IMAGE", "secure-exec:latest")
APPARMOR = os.environ.get("SECURE_EXEC_APPARMOR", "secure-exec-userns")

# Minimal runtime posture: NON-root container, NO --privileged, NO extra caps.
# Mirrors the Makefile DOCKER_RUN_FLAGS so tests exercise the real hardened
# posture (see CLAUDE.md "Why these run flags").
#   Outer-container hardening (assume the jail can be escaped):
#     --cap-drop ALL, no-new-privileges, --read-only + tmpfs /tmp,
#     --pids-limit, --memory/--cpus
#   nsjail-enablement (least privilege to build the rootless jail):
#     seccomp=unconfined   -> nsjail applies its OWN (stricter) seccomp
#     apparmor=<profile>   -> scoped userns permission (host keeps the restrict on)
#     systempaths=unconfined -> unmask /proc so nsjail can mount procfs in its PID ns
DOCKER_RUN = [
    "docker", "run", "--rm", "-i",
    "--network", "none",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
    "--pids-limit", "256",
    "--memory", "1g", "--memory-swap", "1g", "--cpus", "2",
    "--security-opt", "seccomp=unconfined",
    "--security-opt", f"apparmor={APPARMOR}",
    "--security-opt", "systempaths=unconfined",
]


class SandboxResult:
    def __init__(self, proc: subprocess.CompletedProcess):
        self.returncode = proc.returncode
        self.raw_stdout = proc.stdout
        self.raw_stderr = proc.stderr
        self.result = None
        # The runner writes JSON on fd 3, which we redirect to stdout in the
        # container, so the last JSON object on stdout is the structured result.
        for line in reversed(proc.stdout.strip().splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    self.result = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue

    @property
    def ok(self) -> bool:
        return bool(self.result and self.result.get("ok"))

    @property
    def stdout(self) -> str:
        return (self.result or {}).get("stdout", "")

    @property
    def error(self) -> str:
        return (self.result or {}).get("error") or ""

    def __repr__(self) -> str:
        return (f"SandboxResult(rc={self.returncode}, ok={self.ok}, "
                f"error={self.error!r}, raw_stderr={self.raw_stderr!r})")


@pytest.fixture(scope="session")
def docker_available():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    check = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        capture_output=True, text=True,
    )
    if check.returncode != 0:
        pytest.skip(f"image {IMAGE} not built; run: docker build -t {IMAGE} .")


@pytest.fixture
def run_in_sandbox(docker_available):
    def _run(code: str, *, time_limit: int = 10, mem_mb: int = 512,
             timeout: int = 60) -> SandboxResult:
        cmd = DOCKER_RUN + [
            "-e", f"SE_TIME_LIMIT={time_limit}",
            "-e", f"SE_MEM_MB={mem_mb}",
            IMAGE, "-",
        ]
        proc = subprocess.run(
            cmd,
            input=textwrap.dedent(code),
            capture_output=True, text=True, timeout=timeout,
        )
        return SandboxResult(proc)
    return _run