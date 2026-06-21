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
# Stage 2: runtime (PRODUCTION target — minimal, no audit tools)
############################
FROM python:3.12-slim-bookworm AS runtime

# Runtime libs nsjail links against (protobuf + libnl). No build tools here.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        libprotobuf32 \
        libnl-route-3-200 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get purge -y --auto-remove

# Default venv (RUNNER ONLY). The runner imports third-party packages ONLY from
# a venv mounted at /venv (PYTHONPATH=/venv/site), never from the image's own
# site-packages. When no user volume is attached, run.sh binds this baked default
# venv as /venv. Built with pip --target (NOT `python -m venv`) so it holds
# packages only, no interpreter; made read-only so nothing can mutate it at
# runtime. The installer image does NOT get this (it builds user venvs instead);
# when the Dockerfile is split (runtime-base -> runner/installer), this step
# moves into the runner target only.
RUN pip install --no-cache-dir --target=/opt/default-venv/site \
        numpy==2.2.1 \
        pandas==2.2.3 \
    && chmod -R a-w /opt/default-venv

COPY --from=build /src/nsjail /usr/local/bin/nsjail

# Application files live under /opt and are world-readable, never writable.
COPY nsjail/python.proto.template /opt/secure-exec/nsjail/python.proto.template
COPY sandbox/runner.py            /opt/secure-exec/sandbox/runner.py
COPY sandbox/run.sh               /opt/secure-exec/sandbox/run.sh
RUN chmod 0755 /opt/secure-exec/sandbox/run.sh \
    && chmod 0444 /opt/secure-exec/nsjail/python.proto.template \
                  /opt/secure-exec/sandbox/runner.py

# Unprivileged runtime user. nsjail builds the inner userns from here; it does
# NOT need to be root in the container.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin sandbox
USER 10001
WORKDIR /home/sandbox

ENTRYPOINT ["/opt/secure-exec/sandbox/run.sh"]

############################
# Stage 3: audit (DEV/AUDIT target — runtime + amicontained)
############################
# Build with: docker build --target audit -t secure-exec:audit .
# This image is identical to the production runtime but adds the amicontained
# binary under /usr/local/bin so it is reachable both directly (outer audit,
# via --entrypoint) and inside the jail (inner audit, since the jail mounts
# /usr read-only and /usr/local/bin lives under it). Keep it OUT of prod.
FROM runtime AS audit
USER 0
COPY --from=amicontained-build /amicontained /usr/local/bin/amicontained
RUN chmod 0555 /usr/local/bin/amicontained
USER 10001
