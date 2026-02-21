# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

sdme is a rewrite of [devctl](https://github.com/fiorix/devctl) — lightweight systemd-nspawn containers with overlayfs. It produces a single binary `sdme` that manages containers from explicit root filesystems, keeping the base rootfs untouched via overlayfs copy-on-write.

Runs on Linux with systemd. Privileged mode (root) uses kernel overlayfs. Rootless mode uses fuse-overlayfs and `systemd-nspawn --private-users=managed`.

## Build & Test

```bash
cargo build --release       # build the binary
cargo test                  # run all tests
cargo test <test_name>      # run a single test
make                        # same as cargo build --release
sudo make install           # install to /usr/local (does NOT rebuild)
```

## Architecture

The project is a single Rust binary (`src/main.rs`) backed by a shared library (`src/lib.rs`). CLI parsing uses clap with derive.

### Core Concepts

- **Overlayfs CoW storage**: each container gets `upper/work/merged/shared` directories under the datadir. The lower layer is the imported rootfs. Privileged mode uses kernel overlayfs; rootless mode uses fuse-overlayfs.
- **Systemd integration**: containers are managed as a systemd template unit (`sdme@.service`). Start/stop goes through D-Bus to systemd. The template unit is auto-installed and auto-updated when content changes.
- **State files**: container metadata persisted as KEY=VALUE files under `{datadir}/state/{name}`.
- **Health checks**: `sdme ps` detects broken containers (missing dirs, missing rootfs) and reports health status.
- **Conflict detection**: prevents name collisions with existing containers and `/var/lib/machines/`.

### CLI Commands

| Command | Description |
|---------|-------------|
| `sdme create` | Create a new container (overlayfs dirs + state file) |
| `sdme start` | Start a container (installs/updates template unit, starts via D-Bus) |
| `sdme join` | Enter a running container (native `setns` + `chroot`, no `nsenter` binary) |
| `sdme stop` | Stop a running container |
| `sdme rm` | Remove containers (stops if running, deletes state + files) |
| `sdme ps` | List containers with status, health, and shared directory |
| `sdme logs` | View container logs (exec's `journalctl`) |
| `sdme rootfs import` | Import a rootfs from directory, tar file, or stdin |
| `sdme rootfs ls` | List imported root filesystems |
| `sdme rootfs rm` | Remove imported root filesystems |
| `sdme config get/set` | View or modify configuration |

### Key Modules

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point (clap derive), command dispatch |
| `src/lib.rs` | Shared types: `State` (KEY=VALUE), `validate_name`, `is_privileged`, `sudo_user` |
| `src/containers.rs` | Container create/remove/join/list, overlayfs directory management |
| `src/systemd.rs` | D-Bus helpers (start/stop/status), template unit generation, env files |
| `src/system_check.rs` | Version checks (systemd, kernel), dependency checks (`find_program`) |
| `src/rootfs.rs` | Rootfs import (directory copy, tar extraction), listing, removal |
| `src/config.rs` | Config file loading/saving (`~/.config/sdme/sdmerc`) |

### Rust Dependencies

- `clap` — CLI parsing (derive)
- `zbus` — D-Bus communication with systemd (blocking API)
- `libc` — syscalls: `setns`, `chroot`, `chdir`, `fork`, `mount`/`umount`
- `anyhow` — error handling
- `serde`/`toml` — config file parsing

### External Dependencies

| Program | Package | Required for |
|---------|---------|--------------|
| `systemd` (>= 257) | `systemd` | All commands (D-Bus communication) |
| `systemd-nspawn` | `systemd-container` | Running containers |
| `journalctl` | `systemd` | `sdme logs` |
| `tar` | `tar` | `sdme rootfs import` |
| `newuidmap` | `uidmap` | `sdme rootfs import` (rootless) |
| `newgidmap` | `uidmap` | `sdme rootfs import` (rootless) |
| `fuse-overlayfs` | `fuse-overlayfs` | `sdme create`, `sdme start` (rootless) |
| `fusermount` | `fuse3` | `sdme start`, `sdme stop` (rootless) |

Dependencies are checked at runtime before use via `system_check::check_dependencies()`, which resolves each binary in PATH and prints the resolved path with `-v`.

## Design Decisions

### Rootless mode (implemented 2026-02-22)

Rootless mode is auto-detected via `euid != 0`. Requires systemd 257+ and kernel 5.11+.

**How it works:**

- **Datadir**: defaults to `~/.local/state/sdme` (respects `XDG_STATE_HOME`) when unprivileged, `/var/lib/sdme` when root.
- **rootfs import**: copies files without `lchown`/`mknod` (skips device nodes, `trusted.*` xattrs) into a user namespace with subordinate UID/GID mappings (via `newuidmap`/`newgidmap`) to preserve ownership.
- **Container create**: creates `upper/work/merged/shared` overlay directories (same as privileged mode). No rootfs copy.
- **Container start**: installs a user-level template unit at `~/.config/systemd/user/sdme@.service`, uses `Connection::session()` (D-Bus session bus). The unit mounts fuse-overlayfs with the rootfs as the lower layer, then runs `systemd-nspawn --private-users=managed --private-network --register=no --boot`. Template unit is auto-updated if content differs. Checks for linger before starting.
- **Container join**: enters the container's namespaces using native `setns()` syscalls (user, mount, UTS, IPC, network, PID) via a `pre_exec` closure — no `nsenter` binary needed. Uses `chroot` + `chdir` to set root and working directory.
- **State file**: records `MODE=rootless` or `MODE=privileged`.

**Limitations:**

- Host-as-rootfs (devctl mode) requires root — UID mapping problems make `/` unusable as a lower layer in user namespaces.
- Device nodes (block/char) are not created during rootless import; nspawn populates `/dev` internally.
- SUID bits are lost in rootless import.
- Containers are not registered with `systemd-machined` (inaccessible to unprivileged users).

**One-time system setup:**

```bash
sudo apt install systemd-container tar uidmap fuse-overlayfs fuse3

# BPF LSM is required by systemd-nsresourced for user namespace support.
# Check: cat /sys/kernel/security/lsm — if "bpf" is missing, add
# lsm=...,bpf to GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub,
# then: sudo update-grub && sudo reboot

sudo systemctl enable --now systemd-nsresourced.socket systemd-mountfsd.socket
```

**One-time user setup:**

```bash
loginctl enable-linger $USER
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER
```
