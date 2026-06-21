#!/usr/bin/env python3
"""In-jail pip installer.

This is the PID-1 process inside the INSTALL jail. It runs `pip install` into
the user's venv (mounted read-write at /venv) and reports a structured JSON
result on fd 3 -- the same contract as runner.py, so the harness parses both
phases identically.

By the time this runs, nsjail has dropped caps, applied seccomp, entered all
namespaces and pivot_root'ed. Network reaches ONLY the egress proxy (enforced by
the container's --internal network topology, not by this code).

Inputs (env, set by run.sh):
  SE_PACKAGES     space-separated package specs to install
  SE_INSTALL_MODE "wheel" (default) -> --only-binary :all:; "source" -> allow sdists
  SE_PROXY_URL    proxy URL for pip (functional only)
Target:
  /venv/site      pip --target dir (the only thing on the runner's PYTHONPATH)
"""
import json
import os
import subprocess
import sys

RESULT_FD = 3
VENV_SITE = "/venv/site"


def _emit(result: dict) -> None:
    payload = json.dumps(result).encode()
    try:
        os.write(RESULT_FD, payload)
    except OSError:
        sys.stdout.write(payload.decode())


def main() -> int:
    packages = (os.environ.get("SE_PACKAGES") or "").split()
    mode = (os.environ.get("SE_INSTALL_MODE") or "wheel").strip().lower()
    proxy = os.environ.get("SE_PROXY_URL") or ""

    if not packages:
        _emit({"ok": False, "error": "no packages given (SE_PACKAGES empty)"})
        return 2
    if mode not in ("wheel", "source"):
        _emit({"ok": False, "error": f"invalid SE_INSTALL_MODE={mode!r} (wheel|source)"})
        return 2

    os.makedirs(VENV_SITE, exist_ok=True)

    cmd = [
        sys.executable, "-m", "pip", "install",
        "--target", VENV_SITE,
        "--no-input",
        "--disable-pip-version-check",
        "--no-cache-dir",
    ]
    if proxy:
        cmd += ["--proxy", proxy]
    if mode == "wheel":
        # Wheels only: no setup.py runs at install time; no compiler needed.
        cmd += ["--only-binary", ":all:"]
    cmd += packages

    proc = subprocess.run(cmd, capture_output=True, text=True)

    result = {
        "ok": proc.returncode == 0,
        "error": None if proc.returncode == 0 else "pip install failed",
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "returncode": proc.returncode,
        "mode": mode,
        "packages": packages,
    }
    _emit(result)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())