# sdme Kube Stack Verification Report

## System Info

| Field | Value |
|-------|-------|
| Date | 2026-03-12T13:12:18+00:00 |
| Hostname | lima-default |
| Kernel | 6.17.0-14-generic |
| systemd | systemd 257 (257.9-0ubuntu2.1) |
| sdme | 0.3.1 |
| Base FS | ubuntu |

## Summary

| Result | Count |
|--------|-------|
| PASS | 1 |
| FAIL | 1 |
| SKIP | 10 |
| Total | 12 |

## Results

| Test | Result |
|------|--------|
| setup-config | PASS |
| create-stack | FAIL |
| patch-prom-config | SKIP |
| start-stack | SKIP |
| redis-active | SKIP |
| redis-exporter-active | SKIP |
| prometheus-active | SKIP |
| redis-ping | SKIP |
| redis-workload | SKIP |
| prometheus-listening | SKIP |
| prometheus-scrape | SKIP |
| ps-kube-column | SKIP |

## Failures

### create-stack

```
config: /root/.config/sdme/sdmerc
copying base rootfs 'ubuntu' to staging directory
pulling registry-1.docker.io/library/redis:latest
no proxy configured
probing https://registry-1.docker.io/v2/
WWW-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
requesting token from https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/redis:pull
obtained bearer token (2657 chars)
fetching manifest: https://registry-1.docker.io/v2/library/redis/manifests/latest
manifest list with 16 entries, selecting linux/arm64
selected platform manifest: sha256:b7e0bf9f5642e27acc72c1f031aa452c29f96f47ec89cf045df14918add7e836
fetching manifest: https://registry-1.docker.io/v2/library/redis/manifests/sha256:b7e0bf9f5642e27acc72c1f031aa452c29f96f47ec89cf045df14918add7e836
image has 7 layer(s)
fetching config blob: sha256:35267b49b0841029c5168ff138d4ea5e820a868ff87c07c1972cc674c41677c4
image config: entrypoint=Some(["docker-entrypoint.sh"]) cmd=Some(["redis-server"]) workdir=Some("/data") user=None
image config: env (1 vars)
image config: exposed ports: 6379/tcp
extracting layer 1/7: sha256:3b66ab8c894cad95899b704e688938517870850391d1349c862c2b09214acb86
downloading blob: sha256:3b66ab8c894cad95899b704e688938517870850391d1349c862c2b09214acb86
downloaded 30140098 bytes
Error: failed to pull image for container 'redis'

Caused by:
    0: failed to open /var/lib/sdme/fs/.layer-0.tmp
    1: No such file or directory (os error 2)
```

