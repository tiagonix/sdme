# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

sdme is a rewrite of [devctl](https://github.com/fiorix/devctl) — lightweight systemd-nspawn containers with overlayfs. It produces two binaries:

- **devctl**: clones the host filesystem copy-on-write for development (install packages, compile, test without touching the host)
- **prodctl**: runs containers from explicit root filesystems, keeping the base rootfs untouched

Both require root and run on Linux with systemd.

## Build & Test

```bash
cargo build --release       # build both binaries
cargo test                  # run all tests
cargo test <test_name>      # run a single test
make                        # same as cargo build --release
sudo make install           # install to /usr/local (does NOT rebuild)
```

## Architecture

The project is a Rust workspace with two thin CLI binaries (`src/bin/devctl.rs`, `src/bin/prodctl.rs`) backed by a shared library (`src/lib.rs`). CLI parsing uses clap with derive.

### Core Concepts

- **Overlayfs CoW storage**: each container gets `upper/work/merged/shared` directories under `/var/lib/{devctl,prodctl}/fs/<name>/`. The lower layer is `/` (host) for devctl or an explicit rootfs for prodctl.
- **Systemd integration**: containers are managed as systemd template units (`devctl@.service`, `prodctl@.service`). Start/stop/status goes through D-Bus to systemd and systemd-machined.
- **State files**: container metadata persisted as KEY=VALUE files under `/var/lib/{devctl,prodctl}/state/<name>.conf`.
- **Health checks**: detect half-broken containers (missing dirs, stale mounts, orphan units) and offer cleanup paths.
- **Conflict detection**: prevents name collisions with `/var/lib/machines/` and other nspawn/machined containers.

### prodctl Extras

- **Dockerfile-like build configs**: `FROM`, `RUN`, `COPY` syntax parsed from config files to build root filesystems
- **OCI image import**: download and extract `.oci.tar.xz` archives with architecture detection; auto-installs systemd/login if missing
- **Root filesystem management**: `fs build`, `fs import`, `fs ls`, `fs rm`

### Key Dependencies (from original)

- `clap` — CLI parsing
- `zbus` — D-Bus communication with systemd (blocking API)
- `libc` — mount/umount syscalls
- `anyhow` — error handling
- `tar`, `flate2`, `xz2` — archive extraction for OCI imports
- `ureq` — HTTP client for downloading images
- `serde`/`serde_json` — OCI manifest parsing

## Design Decisions

### Default datadir stays at `/var/lib/sdme` (decided 2026-02-21)

We investigated moving the default `datadir` from `/var/lib/sdme` to `~/.local/share/sdme/` to allow rootless `create` operations. The conclusion was **do not change it** for now. Full analysis is in `.claude/plans/elegant-shimmying-bubble.md`. Key points:

- **Kernel support exists**: kernel 6.8 supports unprivileged overlayfs (since 5.11) inside user namespaces with `-o userxattr`.
- **systemd blocks it**: unprivileged `systemd-nspawn --directory=` requires **systemd 257+**. Current target (Ubuntu 24.04) ships systemd 255. `systemd-machined` is also inaccessible to unprivileged users, breaking D-Bus container management.
- **Split-privilege problem**: if `create` runs as a normal user but `start` needs `sudo`, root resolves `~/.local/share/sdme/` to `/root/.local/share/sdme/` — a different path. This makes the default datadir useless without explicit `--config` overrides.
- **devctl's host-as-lowerdir**: using `/` as the overlayfs lower layer in a user namespace causes UID mapping problems (system files appear as `nobody`).
- **Revisit when**: systemd 257+ is available on the target platform (likely Ubuntu 25.04+). At that point, design rootless mode holistically: user session bus, user-level template units, unprivileged nspawn, and proper UID mapping.
