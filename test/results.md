# Test Results

Last verified: 2026-03-16

System: Linux 6.19.6-2-cachyos (x86_64), systemd 259, sdme 0.4.1, AppArmor enabled

See [README.md](README.md) for how to run the tests and known limitations.

## Summary

| # | Test Suite | Status | Passed | Failed | Skipped | Total |
|---|-----------|--------|--------|--------|---------|-------|
| 1 | verify-usage.sh | PASS | 49 | 0 | 0 | 49 |
| 2 | verify-security.sh | PASS | 22 | 0 | 10 | 32 |
| 3 | verify-oci.sh | PASS | 20 | 0 | 0 | 20 |
| 4 | verify-pods.sh | PASS | 9 | 0 | 0 | 9 |
| 5 | verify-export.sh | PASS | 12 | 0 | 0 | 12 |
| 6 | verify-matrix.sh | FAIL | 225 | 3 | 3 | 231 |
| 7 | verify-nixos.sh | FAIL | 9 | 1 | 4 | 14 |
| 8 | verify-kube-L1-basic.sh | PASS | 14 | 0 | 0 | 14 |
| 9 | verify-kube-L2-spec.sh | PASS | 12 | 0 | 0 | 12 |
| 10 | verify-kube-L2-probes.sh | PASS | 41 | 0 | 0 | 41 |
| 11 | verify-kube-L2-security.sh | PASS | 17 | 0 | 0 | 17 |
| 12 | verify-kube-L3-volumes.sh | PASS | 39 | 0 | 0 | 39 |
| 13 | verify-kube-L3-secrets.sh | PASS | 16 | 0 | 0 | 16 |
| 14 | verify-kube-L4-networking.sh | PASS | 6 | 0 | 0 | 6 |
| 15 | verify-kube-L5-redis-stack.sh | PASS | 6 | 0 | 0 | 6 |
| 16 | verify-kube-L6-gitea-stack.sh | PASS | 15 | 0 | 0 | 15 |

**Totals: 512 passed, 4 failed, 17 skipped (533 tests) — 14/16 suites pass**

## Remaining Failures

### verify-matrix.sh — openSUSE hardened OCI apps (3 failures, 3 skips)

Hardened OCI apps (nginx, redis, postgresql) on openSUSE Tumbleweed fail with:

```
systemd-nspawn: Failed to adjust UID/GID shift of OS tree: Operation not permitted
```

**Root cause:** openSUSE Tumbleweed ships `/usr/bin/newuidmap` and
`/usr/bin/newgidmap` with `security.capability` xattrs (file capabilities for
`CAP_SETUID` and `CAP_SETGID`) instead of the setuid bit used by other distros.
The kernel refuses to create an idmapped mount (`--private-users-ownership=auto`)
when the filesystem contains `security.capability` xattrs because they cannot be
safely remapped across user namespace boundaries.

**Verified:** stripping the xattrs (`setfattr -x security.capability`) on these
two files fixes the boot. All other distros (Debian, Ubuntu, Fedora, CentOS,
AlmaLinux, Arch Linux) pass hardened tests because they use setuid bits instead.

**Fix:** strip `security.capability` xattrs during rootfs import.

### verify-nixos.sh — OCI app boot failure (1 failure, 4 skips)

NixOS OCI app container (nginx on NixOS base) fails to start. Plain NixOS
containers boot fine.

**Root cause:** NixOS manages `/etc` entirely via its activation script, which
replaces `/etc/systemd/system` with a symlink to the Nix store. sdme's OCI app
setup writes unit files (`sdme-oci-*.service`) into `/etc/systemd/system` in the
overlayfs upper layer, causing the NixOS activation to fail:

```
/etc/systemd/system directory contains user files. Symlinking may fail.
could not create symlink /etc/systemd/system
Unit default.target not found.
```

Without working targets, systemd crashes the container. Supporting OCI apps on
NixOS would require a NixOS-specific unit placement strategy.

## Skipped Tests

- **verify-security.sh** (10 skips): AppArmor profile enforcement and multi-distro
  `--userns` boot tests skipped when the required rootfs or AppArmor profiles are
  not pre-installed.
- **verify-nixos.sh** (4 skips): OCI app service, logs, curl-port, and curl-content
  tests skipped because the OCI container fails to boot (see above).
- **verify-matrix.sh** (3 skips): openSUSE hardened OCI app service checks skipped
  because the containers fail to boot (see above).
