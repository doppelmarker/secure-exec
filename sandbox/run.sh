#!/bin/sh
# Entrypoint for the secure-exec sandbox container.
#
# Usage:
#   run.sh < user_script.py            # read job from stdin
#   run.sh /path/to/script.py          # run a specific file
#
# It builds a per-job directory, renders the nsjail config, and execs nsjail.
#
# Env knobs:
#   SE_TIME_LIMIT   wall/CPU seconds (default 10)
#   SE_MEM_MB       address-space limit in MB (default 512)
set -eu

TIME_LIMIT="${SE_TIME_LIMIT:-10}"
MEM_MB="${SE_MEM_MB:-512}"

TEMPLATE="/opt/secure-exec/nsjail/python.proto.template"
RUNNER="/opt/secure-exec/sandbox/runner.py"

# --- Stage the job in a private, read-only-to-the-jail directory ---
JOB_DIR="$(mktemp -d /tmp/job.XXXXXX)"
cleanup() { rm -rf "$JOB_DIR"; }
trap cleanup EXIT INT TERM

if [ "$#" -ge 1 ] && [ "$1" != "-" ]; then
    cp "$1" "$JOB_DIR/job.py"
else
    cat > "$JOB_DIR/job.py"
fi
cp "$RUNNER" "$JOB_DIR/runner.py"
chmod -R a-w "$JOB_DIR"

# --- Per-arch seccomp extras ---
# kafel only defines some syscall identifiers on certain architectures. We add
# each extra syscall to the KILL list only on arches where it compiles, so the
# policy always loads and every arch gets the strictest list it can enforce.
# The value, when non-empty, continues the comma-separated KILL list, so it
# must start with a leading comma.
case "$(uname -m)" in
    x86_64|amd64)
        # Verified to compile in kafel on x86_64 (umount2 is NOT defined even
        # here, so it is intentionally absent).
        SECCOMP_ARCH_EXTRA=", umount, kexec_file_load, _sysctl, uselib, ustat" ;;
    aarch64|arm64)
        # umount/kexec_file_load and the legacy x86 syscalls above are NOT
        # defined by kafel on arm64; the core list is the strictest available.
        SECCOMP_ARCH_EXTRA="" ;;
    *)
        SECCOMP_ARCH_EXTRA="" ;;
esac

# --- Render the nsjail config from the template ---
CONFIG="$(mktemp /tmp/nsjail.XXXXXX.cfg)"
trap 'cleanup; rm -f "$CONFIG"' EXIT INT TERM

sed \
    -e "s|{TIME_LIMIT}|${TIME_LIMIT}|g" \
    -e "s|{RLIMIT_AS_MB}|${MEM_MB}|g" \
    -e "s|{JOB_DIR}|${JOB_DIR}|g" \
    -e "s|{SECCOMP_ARCH_EXTRA}|${SECCOMP_ARCH_EXTRA}|g" \
    "$TEMPLATE" > "$CONFIG"

# fd 3 carries the runner's structured JSON result back out.
exec 3>&1

# --- Run ---
# --config drives all the hardening; we only point it at the interpreter.
exec nsjail \
    --config "$CONFIG" \
    -- /usr/local/bin/python3 -I -B /sandbox/runner.py