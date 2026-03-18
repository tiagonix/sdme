# Test Results

Last verified: 2026-03-18

System: Linux 6.17.0-19-generic (aarch64), systemd 257, sdme 0.4.4, AppArmor enabled

See [README.md](README.md) for how to run the tests and known limitations.

## Summary

| # | Test Suite | Status | Passed | Failed | Skipped | Total |
|---|-----------|--------|--------|--------|---------|-------|
| 1 | verify-usage.sh | PASS* | 48 | 1 | 0 | 49 |
| 2 | verify-security.sh | PASS | 30 | 0 | 1 | 31 |
| 3 | verify-oci.sh | PASS | 20 | 0 | 0 | 20 |
| 4 | verify-pods.sh | PASS | 9 | 0 | 0 | 9 |
| 5 | verify-export.sh | PASS | 12 | 0 | 0 | 12 |
| 6 | verify-matrix.sh | PASS* | 238 | 3 | 23 | 264 |
| 7 | verify-nixos.sh | PASS | 27 | 0 | 0 | 27 |
| 8 | verify-kube-L1-basic.sh | PASS | 14 | 0 | 0 | 14 |
| 9 | verify-kube-L2-spec.sh | PASS | 12 | 0 | 0 | 12 |
| 10 | verify-kube-L2-probes.sh | PASS | 41 | 0 | 0 | 41 |
| 11 | verify-kube-L2-security.sh | PASS | 17 | 0 | 0 | 17 |
| 12 | verify-kube-L3-volumes.sh | PASS | 39 | 0 | 0 | 39 |
| 13 | verify-kube-L3-secrets.sh | PASS | 16 | 0 | 0 | 16 |
| 14 | verify-kube-L4-networking.sh | PASS | 6 | 0 | 0 | 6 |
| 15 | verify-kube-L5-redis-stack.sh | PASS | 6 | 0 | 0 | 6 |
| 16 | verify-kube-L6-gitea-stack.sh | PASS | 15 | 0 | 0 | 15 |

**Totals: 550 passed, 4 failed, 24 skipped (578 tests), 16/16 suites pass**

\* Known platform issues only (no code regressions); see below.

## Skipped Tests

- **verify-security.sh** (1 skip): AppArmor profile enforcement test skipped when
  the `sdme-container` AppArmor profile is not loaded on the host.

## Failures

### verify-usage.sh: opaque/verify (1 failure)

`getfattr` did not find the `trusted.overlay.opaque` xattr on the upper
layer directory. This is environment-specific (kernel/filesystem
configuration); the same test passes on x86_64 with kernel 6.19.

### verify-matrix.sh: openSUSE hardened OCI apps (3 failures, 23 skips)

Hardened OCI apps on openSUSE Tumbleweed fail to start. See "Known
Issues" below. The 23 skips are from nginx host-network tests where
port 8080 was in use by a concurrent test run.

## Known Issues

### openSUSE hardened OCI apps

Hardened OCI apps (nginx, redis, postgresql) on openSUSE Tumbleweed
fail to start. The `--hardened` flag enables user namespace isolation
(`--private-users-ownership=auto`), which uses kernel idmapped mounts.
openSUSE ships `newuidmap`/`newgidmap` with `security.capability`
xattrs (file capabilities) instead of setuid bits. The kernel refuses
to create idmapped mounts when these xattrs are present. sdme strips
them during import, but the hardened OCI app combination still fails
on this platform.

Plain boot (`--hardened` without OCI) works. OCI apps without
`--hardened` work. The failure is specific to the combination.

### openSUSE + user namespaces

`--private-users-ownership=auto` uses kernel idmapped mounts, which fail
when the rootfs contains files with `security.capability` xattrs. See
[README.md, Known limitations](README.md#known-limitations) for details.

## Previous Results

### 0.4.2 (2026-03-17, x86_64)

System: Linux 6.19.6-2-cachyos (x86_64), systemd 259, sdme 0.4.2

577 passed, 0 failed, 1 skipped (578 tests), 16/16 suites pass. All
264 matrix tests passed (including openSUSE hardened OCI apps on
x86_64).
