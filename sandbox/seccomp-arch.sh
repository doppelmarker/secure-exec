# Shared helper sourced by run.sh and install.sh.
#
# Per-arch seccomp extras: kafel only defines some syscall identifiers on certain
# architectures. We add each extra syscall to the KILL list only on arches where
# it compiles, so the policy always loads and every arch gets the strictest list
# it can enforce. The value, when non-empty, continues the comma-separated KILL
# list, so it must start with a leading comma.
seccomp_arch_extra() {
    case "$(uname -m)" in
        x86_64|amd64)
            # Verified to compile in kafel on x86_64 (umount2 is NOT defined even
            # here, so it is intentionally absent).
            printf '%s' ", umount, kexec_file_load, _sysctl, uselib, ustat" ;;
        *)
            # umount/kexec_file_load and the legacy x86 syscalls are NOT defined
            # by kafel on arm64 (etc.); the core list is the strictest available.
            printf '%s' "" ;;
    esac
}