#!/bin/sh
# Entrypoint for the secure-exec INSTALLER image (install phase).
#
# Runs `pip install` UNDER nsjail into the user venv mounted read-write at /venv.
# Network reaches ONLY the egress proxy (enforced by the container's --internal
# Docker network topology, not by this script). Arbitrary install/build code is
# therefore jailed: caps dropped, seccomp applied, pivot_root'ed.
#
# Usage:
#   install.sh <pkg> [<pkg> ...]   # package specs, as plain args
#
# Env knobs:
#   SE_INSTALL_TIME_LIMIT  wall/CPU seconds (default 300)
#   SE_INSTALL_MEM_MB      address-space limit in MB (default 2048)
#   SE_INSTALL_MODE        wheel (default) | source
#   SE_PROXY_URL           egress proxy URL (functional only; topology enforces)
#
# installer.py writes a structured JSON result on fd 3 (redirected to stdout).
set -eu

SANDBOX_DIR="/opt/secure-exec/sandbox"
TEMPLATE="/opt/secure-exec/nsjail/install.proto.template"
. "$SANDBOX_DIR/seccomp-arch.sh"

PACKAGES="$*"
if [ -z "$PACKAGES" ]; then
    echo "install.sh: no packages given" >&2
    exit 2
fi

TIME_LIMIT="${SE_INSTALL_TIME_LIMIT:-300}"
MEM_MB="${SE_INSTALL_MEM_MB:-2048}"
INSTALL_MODE="${SE_INSTALL_MODE:-wheel}"
PROXY_URL="${SE_PROXY_URL:-}"

# --- Stage the installer driver read-only ---
JOB_DIR="$(mktemp -d /tmp/job.XXXXXX)"
CONFIG="$(mktemp /tmp/nsjail.XXXXXX.cfg)"
trap 'rm -rf "$JOB_DIR" "$CONFIG"' EXIT INT TERM
cp "$SANDBOX_DIR/installer.py" "$JOB_DIR/installer.py"
chmod -R a-w "$JOB_DIR"

# PROXY_URL is rendered into the proto's HTTP(S)_PROXY env (functional only).
sed \
    -e "s|{TIME_LIMIT}|${TIME_LIMIT}|g" \
    -e "s|{RLIMIT_AS_MB}|${MEM_MB}|g" \
    -e "s|{JOB_DIR}|${JOB_DIR}|g" \
    -e "s|{PROXY_URL}|${PROXY_URL}|g" \
    -e "s|{SECCOMP_ARCH_EXTRA}|$(seccomp_arch_extra)|g" \
    "$TEMPLATE" > "$CONFIG"

# fd 3 carries installer.py's structured JSON result back out.
exec 3>&1

# installer.py reads SE_PACKAGES / SE_INSTALL_MODE / SE_PROXY_URL. We pass them
# through nsjail with --env (the proto starts from an empty environment).
exec nsjail \
    --config "$CONFIG" \
    --env "SE_PACKAGES=${PACKAGES}" \
    --env "SE_INSTALL_MODE=${INSTALL_MODE}" \
    --env "SE_PROXY_URL=${PROXY_URL}" \
    -- /usr/local/bin/python3 -B /sandbox/installer.py