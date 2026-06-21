# syntax=docker/dockerfile:1.7
#
# Minimal, secure image for the secure-exec Python sandbox.
#
# Liz Rice's "Container Security" guidance applied:
#   - multi-stage build: compilers/headers never reach the final image
#   - pinned base images (digest-pinnable; tag pinned here for readability)
#   - run as a non-root user; the sandbox does NOT need root
#   - only the packages required at runtime are installed
#   - no package manager / build tools in the final stage
#
# nsjail itself needs a kernel that permits unprivileged user namespaces.
# Under Colima (vz) on Apple Silicon this is available. The CONTAINER must be
# allowed to create user namespaces (see README: --security-opt + sysctl), but
# the process inside runs UNPRIVILEGED — nsjail creates the userns from there.

############################
# Stage 1: build nsjail
############################
FROM debian:bookworm-slim AS build

ARG NSJAIL_VERSION=3.4
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        build-essential \
        make \
        pkg-config \
        protobuf-compiler \
        libprotobuf-dev \
        libnl-route-3-dev \
        bison \
        flex \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch "${NSJAIL_VERSION}" \
        https://github.com/google/nsjail.git . \
    && make -j"$(nproc)" \
    && strip nsjail

############################
# Stage 1b: build amicontained (audit only; never in the prod image)
############################
# amicontained is Jess Frazelle's container-introspection tool: it reports the
# runtime, namespaces, capabilities, seccomp/apparmor and blocked syscalls —
# used here to audit BOTH the outer container and the jail.
#
# Pinned to v0.4.5: it is the last version whose source compiles for BOTH amd64
# and arm64. Later commits reference arch-specific syscall constants
# (unix.SYS_OPEN/SELECT/FORK/...) that don't exist in the arm64 syscall ABI, so
# they only build for amd64. Building v0.4.5 from source gives us a NATIVE arm64
# binary, so the seccomp/syscall audit faithfully reflects our real arm64 policy
# (no emulation mismatch).
FROM golang:1.22-bookworm AS amicontained-build

ARG AMICONTAINED_VERSION=v0.4.5
ENV CGO_ENABLED=0
WORKDIR /src
RUN git clone --depth 1 --branch "${AMICONTAINED_VERSION}" \
        https://github.com/genuinetools/amicontained.git . \
    && go build -o /amicontained . \
    && test -x /amicontained

############################
# Stage 2: runtime-base (shared by runner + installer; NOT a runnable target)
############################
# Everything common to both phases: the nsjail binary, its runtime libs, the
# shared app files, and the unprivileged sandbox user. The runner and installer
# targets extend this with phase-specific pieces (default venv / pip+proxy).
FROM python:3.12-slim-bookworm AS runtime-base

# Runtime libs nsjail links against (protobuf + libnl). No build tools here.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        libprotobuf32 \
        libnl-route-3-200 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get purge -y --auto-remove

COPY --from=build /src/nsjail /usr/local/bin/nsjail

# The ONLY app file shared by both phases: the per-arch seccomp helper, sourced
# by both run.sh and install.sh. Phase-specific files (entrypoint script, proto
# template, driver .py) are copied in the respective targets so each image ships
# only its own code path.
COPY sandbox/seccomp-arch.sh /opt/secure-exec/sandbox/seccomp-arch.sh
RUN chmod 0444 /opt/secure-exec/sandbox/seccomp-arch.sh

# Unprivileged runtime user. nsjail builds the inner userns from here; it does
# NOT need to be root in the container.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin sandbox

############################
# Stage 2a: runner (PRODUCTION exec target — minimal, no pip/network/audit)
############################
# Build with: docker build --target runner -t secure-exec-runner:latest .
# Runs untrusted user code with NO network, read-only rootfs, against a single
# mounted venv. Carries NO pip-at-runtime, NO proxy, NO build tools, NO install.sh.
FROM runtime-base AS runner

# Default venv (RUNNER ONLY). The runner imports third-party packages ONLY from
# a venv mounted at /venv (PYTHONPATH=/venv/site), never from the image's own
# site-packages. When no user volume is attached, run.sh binds this baked default
# venv as /venv. Built with pip --target (NOT `python -m venv`) so it holds
# packages only, no interpreter; made read-only so nothing can mutate it at
# runtime.
RUN pip install --no-cache-dir --target=/opt/default-venv/site \
        numpy==2.2.1 \
        pandas==2.2.3 \
    && chmod -R a-w /opt/default-venv

COPY sandbox/run.sh               /opt/secure-exec/sandbox/run.sh
COPY sandbox/runner.py            /opt/secure-exec/sandbox/runner.py
COPY nsjail/python.proto.template /opt/secure-exec/nsjail/python.proto.template
RUN chmod 0755 /opt/secure-exec/sandbox/run.sh \
    && chmod 0444 /opt/secure-exec/sandbox/runner.py \
                  /opt/secure-exec/nsjail/python.proto.template

USER 10001
WORKDIR /home/sandbox
ENTRYPOINT ["/opt/secure-exec/sandbox/run.sh"]

############################
# Stage 2b: installer-wheel (installs PyPI wheels into a user venv, under nsjail)
############################
# Build with: docker build --target installer-wheel -t secure-exec-installer:latest .
# Runs `pip install` UNDER nsjail into a per-user /venv volume, reaching ONLY the
# egress proxy. Wheel mode: --only-binary :all:, so NO build toolchain is needed
# and no setup.py runs at install time. Carries NO run.sh / runner / default venv.
FROM runtime-base AS installer-wheel

COPY sandbox/install.sh            /opt/secure-exec/sandbox/install.sh
COPY sandbox/installer.py          /opt/secure-exec/sandbox/installer.py
COPY nsjail/install.proto.template /opt/secure-exec/nsjail/install.proto.template
RUN chmod 0755 /opt/secure-exec/sandbox/install.sh \
    && chmod 0444 /opt/secure-exec/sandbox/installer.py \
                  /opt/secure-exec/nsjail/install.proto.template

# Pre-create /venv owned by the unprivileged user. Docker copies this ownership
# onto a freshly-created empty volume mounted here, so pip (running as namespaced
# root -> host uid 10001) can write the venv. Without this the new volume is
# root-owned and the install fails with EACCES on /venv/site.
RUN mkdir -p /venv && chown 10001:10001 /venv

USER 10001
WORKDIR /home/sandbox
ENTRYPOINT ["/opt/secure-exec/sandbox/install.sh"]

############################
# Stage 2c: installer-source (installer-wheel + a build toolchain for sdists)
############################
# Build with: docker build --target installer-source -t secure-exec-installer:source .
# Same as installer-wheel but adds gcc/headers so sdists can be compiled when the
# caller opts into SE_INSTALL_MODE=source. Build code runs INSIDE the install
# jail (caps dropped, seccomp, egress limited to the proxy). Larger attack
# surface than wheel mode -> opt-in only.
FROM installer-wheel AS installer-source
USER 0
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libc6-dev \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*
USER 10001

############################
# Stage 2d: tinyproxy (egress proxy — the only host that reaches PyPI)
############################
# Build with: docker build --target tinyproxy -t secure-exec-proxy:latest .
# Forward proxy that allow-lists pypi.org + files.pythonhosted.org. The installer
# container reaches it over an --internal Docker network; this proxy alone joins
# an egress network to reach PyPI.
FROM debian:bookworm-slim AS tinyproxy
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        tinyproxy \
    && rm -rf /var/lib/apt/lists/*
COPY proxy/tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY proxy/allowlist      /etc/tinyproxy/allowlist
RUN chmod 0444 /etc/tinyproxy/tinyproxy.conf /etc/tinyproxy/allowlist
USER nobody
EXPOSE 8888
# -d: run in the foreground (PID 1, logs to stdout).
ENTRYPOINT ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]

############################
# Stage 3: audit (DEV/AUDIT target — runner + amicontained)
############################
# Build with: docker build --target audit -t secure-exec:audit .
# Identical to the runner but adds the amicontained binary under /usr/local/bin
# so it is reachable both directly (outer audit, via --entrypoint) and inside the
# jail (inner audit, since the jail mounts /usr read-only). Keep it OUT of prod.
FROM runner AS audit
USER 0
COPY --from=amicontained-build /amicontained /usr/local/bin/amicontained
RUN chmod 0555 /usr/local/bin/amicontained
USER 10001
