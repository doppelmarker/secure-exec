#!/usr/bin/env python3
"""In-sandbox runner.

This is the PID-1 Python process inside the nsjail jail. It executes the
user's script (mounted read-only at /sandbox/job.py) and reports a structured
result on fd 3 so the harness can distinguish runner output from the user
program's own stdout/stderr.

It deliberately does almost nothing privileged: by the time it runs, nsjail
has already dropped caps, applied seccomp, entered all namespaces and
pivot_root'ed into the minimal rootfs. The runner just provides clean
result reporting and a small amount of in-process hardening.
"""
import io
import json
import os
import runpy
import sys
import traceback

USER_SCRIPT = "/sandbox/job.py"
RESULT_FD = 3


def _emit(result: dict) -> None:
    payload = json.dumps(result).encode()
    try:
        os.write(RESULT_FD, payload)
    except OSError:
        # fd 3 not wired up (e.g. running standalone) -> fall back to stdout.
        sys.stdout.write(payload.decode())


def main() -> int:
    if not os.path.exists(USER_SCRIPT):
        _emit({"ok": False, "error": "no user script at /sandbox/job.py"})
        return 2

    # Capture the user program's stdout/stderr separately from our result.
    out, err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err

    result = {"ok": True, "error": None}
    rc = 0
    try:
        # run_path executes job.py as __main__ in a fresh namespace.
        runpy.run_path(USER_SCRIPT, run_name="__main__")
    except SystemExit as e:
        rc = int(e.code) if isinstance(e.code, int) else (0 if e.code is None else 1)
    except BaseException:  # noqa: BLE001 - report everything the job raised
        result["ok"] = False
        result["error"] = traceback.format_exc()
        rc = 1
    finally:
        sys.stdout, sys.stderr = old_out, old_err
        result["stdout"] = out.getvalue()
        result["stderr"] = err.getvalue()
        result["returncode"] = rc

    _emit(result)
    return rc


if __name__ == "__main__":
    sys.exit(main())