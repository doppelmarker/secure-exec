#!/bin/sh
# Entrypoint for the secure-exec RUNNER image (exec phase).
#
# Runs untrusted user code with NO network, read-only rootfs, against a single
# read-only venv (/venv/site on PYTHONPATH). The companion installer image has a
# separate entrypoint, install.sh.
#
# Usage:
#   run.sh -                 # read the script from stdin
#   run.sh /path/script.py   # run a specific file
#
# Env knobs:
#   SE_TIME_LIMIT   wall/CPU seconds (default 10)
#   SE_MEM_MB       address-space limit in MB (default 512)
#
# The structured JSON result is written by runner.py on fd 3 (redirected to
# stdout here) so it never collides with the program's own stdout.
set -eu

SANDBOX_DIR="/opt/secure-exec/sandbox"
TEMPLATE="/opt/secure-exec/nsjail/python.proto.template"
. "$SANDBOX_DIR/seccomp-arch.sh"

TIME_LIMIT="${SE_TIME_LIMIT:-10}"
MEM_MB="${SE_MEM_MB:-512}"

# --- Stage the job + runner in a private, read-only-to-the-jail directory ---
JOB_DIR="$(mktemp -d /tmp/job.XXXXXX)"
CONFIG="$(mktemp /tmp/nsjail.XXXXXX.cfg)"
trap 'rm -rf "$JOB_DIR" "$CONFIG"' EXIT INT TERM

if [ "$#" -ge 1 ] && [ "$1" != "-" ]; then
    cp "$1" "$JOB_DIR/job.py"
else
    cat > "$JOB_DIR/job.py"
fi
cp "$SANDBOX_DIR/runner.py" "$JOB_DIR/runner.py"
chmod -R a-w "$JOB_DIR"

# --- Select the single venv to mount at /venv ---
# If the orchestrator attached a user volume with a populated /venv/site, use it;
# otherwise fall back to the default venv baked into the image (numpy + pandas).
# The jail config is uniform either way: one read-only /venv, /venv/site on path.
if [ -d /venv/site ]; then
    VENV_SRC="/venv"
else
    VENV_SRC="/opt/default-venv"
fi

# --- Render the nsjail config from the template ---
sed \
    -e "s|{TIME_LIMIT}|${TIME_LIMIT}|g" \
    -e "s|{RLIMIT_AS_MB}|${MEM_MB}|g" \
    -e "s|{JOB_DIR}|${JOB_DIR}|g" \
    -e "s|{VENV_SRC}|${VENV_SRC}|g" \
    -e "s|{SECCOMP_ARCH_EXTRA}|$(seccomp_arch_extra)|g" \
    "$TEMPLATE" > "$CONFIG"

# fd 3 carries the runner's structured JSON result back out.
exec 3>&1

# -B: don't write .pyc (the rootfs is read-only anyway). We do NOT use -I
# (isolated mode) because it would make CPython ignore PYTHONPATH, which is how
# we point the job at the single mounted venv (/venv/site). -I's other
# protections are already provided by the jail: keep_env:false gives a controlled
# environment, HOME=/tmp is a fresh tmpfs (no user site-packages), and /sandbox
# is a read-only dir holding only our own files.
exec nsjail \
    --config "$CONFIG" \
    -- /usr/local/bin/python3 -B /sandbox/runner.py