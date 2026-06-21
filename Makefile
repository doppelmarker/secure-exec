# --- Images (two-phase model: runner executes code, installer builds venvs) ---
RUNNER_IMAGE    ?= secure-exec-runner:latest
INSTALLER_IMAGE ?= secure-exec-installer:latest
PROXY_IMAGE     ?= secure-exec-proxy:latest
AUDIT_IMAGE     ?= secure-exec:audit
# Back-compat alias: the runner is the original sandbox image.
IMAGE           ?= $(RUNNER_IMAGE)

APPARMOR_PROFILE ?= secure-exec-userns

# wheel (default, no compiler) | source (adds gcc/headers for sdists).
SE_INSTALL_MODE ?= wheel

# --- Per-user venv orchestration knobs ---
USER ?=                                 # per-user id, e.g. USER=alice
PKGS ?=                                 # space-separated packages, e.g. PKGS="numpy pandas"
VENV_VOLUME      ?= se-venv-$(USER)     # per-user Docker volume name
VENV_SIZE_BYTES  ?= 1073741824          # 1 GiB cap for a user venv
PROXY_NET        ?= se-proxy-net        # --internal net: installer <-> proxy ONLY
EGRESS_NET       ?= se-egress-net       # proxy's route to the internet
PROXY_NAME       ?= se-proxy            # running proxy container name
PROXY_URL        ?= http://$(PROXY_NAME):8888

# Use BuildKit (buildx) rather than the deprecated legacy builder.
export DOCKER_BUILDKIT = 1

# Runtime hardening flags. We grant NO extra capabilities and --privileged is
# never used. See CLAUDE.md "Why these run flags" for the full rationale.
#
# Outer-container hardening (assume the jail CAN be escaped -> the container is
# the next wall). Verified with amicontained:
#   --cap-drop ALL                -> empty the bounding set (nsjail's userns
#                                    grants the namespaced caps it needs)
#   no-new-privileges             -> block setuid/fscaps escalation in container
#   --read-only + tmpfs /tmp      -> immutable rootfs; nsjail writes only to /tmp
#   --pids-limit                  -> outer fork-bomb ceiling (complements rlimit_nproc)
#   --memory/--cpus               -> outer resource ceiling
#
# nsjail-enablement (least privilege needed to BUILD the rootless jail):
#   seccomp=unconfined            -> nsjail applies its OWN (stricter) seccomp
#   apparmor=$(APPARMOR_PROFILE)  -> scoped permission to create a user namespace
#                                    (host keeps apparmor_restrict_unprivileged_userns=1)
#   systempaths=unconfined        -> unmask /proc so nsjail can mount procfs in its PID ns
DOCKER_RUN_FLAGS = --rm -i --network none \
	--cap-drop ALL \
	--security-opt no-new-privileges \
	--read-only \
	--tmpfs /tmp:rw,nosuid,nodev,size=128m \
	--pids-limit 256 \
	--memory 1g --memory-swap 1g --cpus 2 \
	--security-opt seccomp=unconfined \
	--security-opt apparmor=$(APPARMOR_PROFILE) \
	--security-opt systempaths=unconfined

.PHONY: build build-runner build-installer build-proxy build-audit \
        apparmor run example test \
        proxy-up proxy-down venv-create venv-remove install-venv exec-venv \
        audit audit-outer audit-inner clean

# Build all images for the two-phase model.
build: build-runner build-installer build-proxy

# Runner: executes untrusted code (no network, RO rootfs, single mounted venv).
build-runner:
	docker build --target runner -t $(RUNNER_IMAGE) .

# Installer: runs pip UNDER nsjail into a user venv, egress only to the proxy.
# SE_INSTALL_MODE selects the target: wheel (no compiler) or source (gcc/headers).
build-installer:
	docker build --target installer-$(SE_INSTALL_MODE) -t $(INSTALLER_IMAGE) .

# Egress proxy: the only host that reaches PyPI (allow-lists pypi.org +
# files.pythonhosted.org).
build-proxy:
	docker build --target tinyproxy -t $(PROXY_IMAGE) .

# Audit image = runner + amicontained. Kept separate so the prod image stays
# minimal (no introspection binary inside the jail).
build-audit:
	docker build --target audit -t $(AUDIT_IMAGE) .

# Load the AppArmor profile into the host kernel (Colima VM). One-time per host
# (re-run after a Colima restart). Requires the colima CLI.
apparmor:
	cat apparmor/$(APPARMOR_PROFILE) | colima ssh -- sudo sh -c \
		'cat > /etc/apparmor.d/$(APPARMOR_PROFILE) && \
		 apparmor_parser -r -W /etc/apparmor.d/$(APPARMOR_PROFILE) && \
		 echo "loaded $(APPARMOR_PROFILE)"'

# Run an ad-hoc script from stdin against the default venv, e.g.:
#   echo 'print(1+1)' | make run
# To run against a user venv, use `make exec-venv USER=... ` instead.
run:
	docker run $(DOCKER_RUN_FLAGS) $(RUNNER_IMAGE) -

example:
	docker run $(DOCKER_RUN_FLAGS) $(RUNNER_IMAGE) - < examples/numpy_pandas.py

# Tests run via uv (dev group provides pytest). uv syncs deps automatically.
# Assumes `make apparmor` has loaded the profile on this host. Builds all images
# the suite needs (runner + installer + proxy).
test: build
	SECURE_EXEC_RUNNER_IMAGE=$(RUNNER_IMAGE) \
	SECURE_EXEC_INSTALLER_IMAGE=$(INSTALLER_IMAGE) \
	SECURE_EXEC_PROXY_IMAGE=$(PROXY_IMAGE) \
	SECURE_EXEC_IMAGE=$(RUNNER_IMAGE) \
	SECURE_EXEC_APPARMOR=$(APPARMOR_PROFILE) \
		uv run pytest tests/ -v

# --- Per-user venv orchestration -----------------------------------------------
# The install topology: an --internal network (PROXY_NET) joins ONLY the installer
# and the proxy, so the installer has NO route to the internet except the proxy.
# The proxy alone joins EGRESS_NET to reach PyPI. This enforces "proxy is the only
# egress" at the network layer (no CAP_NET_ADMIN needed) and maps to a K8s
# NetworkPolicy later. See CLAUDE.md "Two-phase model".

# Start the egress proxy on both networks. Idempotent-ish (ignores "exists").
proxy-up:
	-docker network create --internal $(PROXY_NET)
	-docker network create $(EGRESS_NET)
	-docker rm -f $(PROXY_NAME) 2>/dev/null
	docker run -d --name $(PROXY_NAME) --network $(PROXY_NET) \
		--cap-drop ALL --security-opt no-new-privileges --read-only \
		--tmpfs /run:rw,nosuid,nodev,size=8m \
		$(PROXY_IMAGE)
	docker network connect $(EGRESS_NET) $(PROXY_NAME)

proxy-down:
	-docker rm -f $(PROXY_NAME)

# Create a per-user venv volume with a ~1GiB cap. NOTE: a hard ON-DISK quota is
# not enforceable with the stock local driver; this size-capped tmpfs volume is a
# RAM-backed approximation (in K8s the PVC size is the real quota). Override with
# VENV_VOLUME / VENV_SIZE_BYTES.
venv-create:
	@test -n "$(USER)" || { echo "USER= is required"; exit 1; }
	docker volume create --driver local \
		--opt type=tmpfs --opt device=tmpfs \
		--opt o=size=$(VENV_SIZE_BYTES) \
		$(VENV_VOLUME)

venv-remove:
	@test -n "$(USER)" || { echo "USER= is required"; exit 1; }
	-docker volume rm $(VENV_VOLUME)

# Install PKGS into USER's venv, under nsjail, egress only to the proxy.
# Requires `make proxy-up` and `make venv-create USER=...` first.
# Example: make install-venv USER=alice PKGS="requests rich"
# The hardening flags mirror DOCKER_RUN_FLAGS but DROP `--network none` (the
# installer must reach the proxy) and attach PROXY_NET instead.
install-venv:
	@test -n "$(USER)" || { echo "USER= is required"; exit 1; }
	@test -n "$(PKGS)" || { echo "PKGS= is required"; exit 1; }
	docker run --rm -i --network $(PROXY_NET) \
		--cap-drop ALL \
		--security-opt no-new-privileges \
		--read-only \
		--tmpfs /tmp:rw,nosuid,nodev,size=1152m \
		--pids-limit 512 \
		--memory 3g --memory-swap 3g --cpus 2 \
		--security-opt seccomp=unconfined \
		--security-opt apparmor=$(APPARMOR_PROFILE) \
		--security-opt systempaths=unconfined \
		-v $(VENV_VOLUME):/venv \
		-e SE_INSTALL_MODE=$(SE_INSTALL_MODE) \
		-e SE_PROXY_URL=$(PROXY_URL) \
		$(INSTALLER_IMAGE) $(PKGS)

# Run a script from stdin against USER's venv (no network, venv read-only).
# Example: echo 'import rich; print(rich.__version__)' | make exec-venv USER=alice
exec-venv:
	@test -n "$(USER)" || { echo "USER= is required"; exit 1; }
	docker run $(DOCKER_RUN_FLAGS) -v $(VENV_VOLUME):/venv:ro $(RUNNER_IMAGE) -

# --- Auditing with amicontained (needs `make build-audit`) ---------------------
# audit-outer: introspect the CONTAINER itself (bypass nsjail via --entrypoint).
#   Shows the caps/seccomp/apparmor/namespaces the outer container is confined by.
# audit-inner: introspect the JAIL (run amicontained AS the sandbox job through
#   the normal entrypoint). Shows what nsjail enforces on untrusted code.
audit: audit-outer audit-inner

audit-outer: build-audit
	@echo "================= OUTER CONTAINER (amicontained) ================="
	docker run $(DOCKER_RUN_FLAGS) \
		--entrypoint /usr/local/bin/amicontained $(AUDIT_IMAGE)

audit-inner: build-audit
	@echo "================= INNER JAIL (amicontained via nsjail) =========="
	@# SE_MEM_MB raised: the Go runtime reserves a large virtual address space
	@# at startup and crashes ("failed to reserve page summary memory") under
	@# the default 512MB rlimit_as. CPython workloads don't need this.
	printf 'import subprocess; subprocess.run(["/usr/local/bin/amicontained"])\n' \
		| docker run $(DOCKER_RUN_FLAGS) -e SE_MEM_MB=4096 $(AUDIT_IMAGE) -

clean:
	-docker image rm $(RUNNER_IMAGE) $(INSTALLER_IMAGE) $(PROXY_IMAGE) $(AUDIT_IMAGE)
	-docker rm -f $(PROXY_NAME)
	-docker network rm $(PROXY_NET) $(EGRESS_NET)