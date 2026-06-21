IMAGE ?= secure-exec:latest
AUDIT_IMAGE ?= secure-exec:audit
APPARMOR_PROFILE ?= secure-exec-userns

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

.PHONY: build build-audit apparmor run example test audit audit-outer audit-inner clean

build:
	docker build -t $(IMAGE) .

# Audit image = production runtime + amicontained. Kept separate so the prod
# image stays minimal (no introspection binary inside the jail).
build-audit:
	docker build --target audit -t $(AUDIT_IMAGE) .

# Load the AppArmor profile into the host kernel (Colima VM). One-time per host
# (re-run after a Colima restart). Requires the colima CLI.
apparmor:
	cat apparmor/$(APPARMOR_PROFILE) | colima ssh -- sudo sh -c \
		'cat > /etc/apparmor.d/$(APPARMOR_PROFILE) && \
		 apparmor_parser -r -W /etc/apparmor.d/$(APPARMOR_PROFILE) && \
		 echo "loaded $(APPARMOR_PROFILE)"'

# Run an ad-hoc script from stdin, e.g.: echo 'print(1+1)' | make run
run:
	docker run $(DOCKER_RUN_FLAGS) $(IMAGE) -

example:
	docker run $(DOCKER_RUN_FLAGS) $(IMAGE) - < examples/numpy_pandas.py

# Tests run via uv (dev group provides pytest). uv syncs deps automatically.
# Assumes `make apparmor` has loaded the profile on this host.
test: build
	SECURE_EXEC_IMAGE=$(IMAGE) SECURE_EXEC_APPARMOR=$(APPARMOR_PROFILE) \
		uv run pytest tests/ -v

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
	-docker image rm $(IMAGE) $(AUDIT_IMAGE)