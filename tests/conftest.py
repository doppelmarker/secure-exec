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
import uuid

import pytest

IMAGE = os.environ.get("SECURE_EXEC_IMAGE", "secure-exec-runner:latest")
RUNNER_IMAGE = os.environ.get("SECURE_EXEC_RUNNER_IMAGE", IMAGE)
INSTALLER_IMAGE = os.environ.get("SECURE_EXEC_INSTALLER_IMAGE",
                                 "secure-exec-installer:latest")
INSTALLER_SOURCE_IMAGE = os.environ.get("SECURE_EXEC_INSTALLER_SOURCE_IMAGE",
                                        "secure-exec-installer:source")
PROXY_IMAGE = os.environ.get("SECURE_EXEC_PROXY_IMAGE", "secure-exec-proxy:latest")
APPARMOR = os.environ.get("SECURE_EXEC_APPARMOR", "secure-exec-userns")

# Network / proxy names for the install topology. Distinct from the Makefile's
# names so a test run doesn't clobber a developer's manual `make proxy-up` setup.
PROXY_NET = "se-test-proxy-net"     # --internal: installer <-> proxy ONLY
EGRESS_NET = "se-test-egress-net"   # proxy's route to the internet
PROXY_NAME = "se-test-proxy"
PROXY_URL = f"http://{PROXY_NAME}:8888"

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
    def stderr(self) -> str:
        return (self.result or {}).get("stderr", "")

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
             timeout: int = 60, volume: str | None = None) -> SandboxResult:
        # When a user venv volume is given, mount it read-only at /venv so the
        # runner picks it up (run.sh sees /venv/site and uses it instead of the
        # baked default). Mirrors `make exec-venv`.
        vol_flags = ["-v", f"{volume}:/venv:ro"] if volume else []
        cmd = DOCKER_RUN + vol_flags + [
            "-e", f"SE_TIME_LIMIT={time_limit}",
            "-e", f"SE_MEM_MB={mem_mb}",
            RUNNER_IMAGE, "-",
        ]
        proc = subprocess.run(
            cmd,
            input=textwrap.dedent(code),
            capture_output=True, text=True, timeout=timeout,
        )
        return SandboxResult(proc)
    return _run


# ---------------------------------------------------------------------------
# Installer (install-phase) fixtures -- heavyweight: real proxy + volumes.
# Used only by tests marked @pytest.mark.installer.
# ---------------------------------------------------------------------------

# Install-phase run flags: mirror DOCKER_RUN but DROP `--network none` (the
# installer must reach the proxy) and give pip more room. The network is attached
# per-call (the proxy net), so it's not baked in here.
INSTALL_RUN = [
    "docker", "run", "--rm", "-i",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=1152m",
    "--pids-limit", "512",
    "--memory", "3g", "--memory-swap", "3g", "--cpus", "2",
    "--security-opt", "seccomp=unconfined",
    "--security-opt", f"apparmor={APPARMOR}",
    "--security-opt", "systempaths=unconfined",
]


def _image_exists(image: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", image],
                          capture_output=True, text=True).returncode == 0


@pytest.fixture(scope="session")
def installer_available(docker_available):
    for img in (INSTALLER_IMAGE, PROXY_IMAGE):
        if not _image_exists(img):
            pytest.skip(f"image {img} not built; run: make build")


@pytest.fixture(scope="session")
def installer_image(installer_available):
    return INSTALLER_IMAGE


@pytest.fixture(scope="session")
def proxy_net(installer_available):
    """Bring up the egress proxy on an --internal net (installer<->proxy only)
    plus an egress net the proxy uses to reach PyPI. Torn down after the session.
    """
    def _run(*args, check=True):
        p = subprocess.run(["docker", *args], capture_output=True, text=True)
        if check and p.returncode != 0:
            raise RuntimeError(f"docker {' '.join(args)} failed: {p.stderr}")
        return p

    # Clean any leftovers from a previous aborted run.
    _run("rm", "-f", PROXY_NAME, check=False)
    _run("network", "rm", PROXY_NET, EGRESS_NET, check=False)

    _run("network", "create", "--internal", PROXY_NET)
    _run("network", "create", EGRESS_NET)
    _run("run", "-d", "--name", PROXY_NAME, "--network", PROXY_NET,
         "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
         "--read-only", "--tmpfs", "/run:rw,nosuid,nodev,size=8m",
         PROXY_IMAGE)
    _run("network", "connect", EGRESS_NET, PROXY_NAME)
    try:
        yield PROXY_NET
    finally:
        _run("rm", "-f", PROXY_NAME, check=False)
        _run("network", "rm", PROXY_NET, EGRESS_NET, check=False)


@pytest.fixture
def user_volume(installer_available):
    """Create a fresh, size-capped per-test venv volume; remove it afterwards."""
    created = []

    def _make() -> str:
        vol = f"se-test-venv-{uuid.uuid4().hex[:10]}"
        subprocess.run(["docker", "volume", "create", vol],
                       capture_output=True, text=True, check=True)
        created.append(vol)
        return vol

    yield _make
    for created_vol in created:
        subprocess.run(["docker", "volume", "rm", "-f", created_vol],
                       capture_output=True, text=True)


@pytest.fixture
def install_in_sandbox(proxy_net):
    """Run the installer image (pip under nsjail) into a volume, via the proxy."""
    def _install(volume: str, packages, *, mode: str = "wheel",
                 index_url: str | None = None, image: str | None = None,
                 extra_env: dict | None = None, timeout: int = 300) -> SandboxResult:
        if isinstance(packages, str):
            packages = packages.split()
        env = ["-e", f"SE_INSTALL_MODE={mode}", "-e", f"SE_PROXY_URL={PROXY_URL}"]
        if index_url:
            env += ["-e", f"SE_INDEX_URL={index_url}"]
        for k, v in (extra_env or {}).items():
            env += ["-e", f"{k}={v}"]
        cmd = INSTALL_RUN + [
            "--network", proxy_net,
            "-v", f"{volume}:/venv",
            *env,
            image or INSTALLER_IMAGE,
            *packages,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return SandboxResult(proc)
    return _install