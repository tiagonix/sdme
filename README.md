# sdme

Lightweight systemd-nspawn containers with overlayfs. Rewrite of [devctl](https://github.com/fiorix/devctl).

Runs on Linux with systemd. Privileged mode (root) uses kernel overlayfs for copy-on-write. Rootless mode uses fuse-overlayfs and `systemd-nspawn --private-users=managed`.

## Dependencies

### Runtime

| Program | Package | Required for |
|---------|---------|--------------|
| `systemd` (>= 257) | `systemd` | All commands (D-Bus communication) |
| `systemd-nspawn` | `systemd-container` | Running containers (`sdme start`) |
| `journalctl` | `systemd` | `sdme logs` |
| `tar` | `tar` | `sdme rootfs import` |
| `newuidmap` | `uidmap` | `sdme rootfs import` (rootless) |
| `newgidmap` | `uidmap` | `sdme rootfs import` (rootless) |
| `fuse-overlayfs` | `fuse-overlayfs` | `sdme create`, `sdme start` (rootless) |
| `fusermount` | `fuse3` | `sdme start`, `sdme stop` (rootless) |

Rootless mode also requires kernel >= 5.11 for user namespace support.

### Install all dependencies (Debian/Ubuntu)

```bash
sudo apt install systemd-container tar uidmap fuse-overlayfs fuse3
```

### One-time system setup (rootless)

Enable BPF LSM (required by `systemd-nsresourced` for user namespace support).
Check if `bpf` is already in the LSM list:

```bash
cat /sys/kernel/security/lsm
```

If `bpf` is missing, add it to the kernel boot parameters:

```bash
# Add lsm=...,bpf to GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, e.g.:
# GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"
sudo update-grub
sudo reboot
```

Enable the systemd services that provide user-namespace UID/GID mapping and
disk image mounting for unprivileged containers:

```bash
sudo systemctl enable --now systemd-nsresourced.socket systemd-mountfsd.socket
```

### One-time user setup (rootless)

Enable linger so user services keep running after logout, and allocate
subordinate UID/GID ranges for user-namespace mapping:

```bash
loginctl enable-linger $USER
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER
```

## Build

```bash
cargo build --release       # build the binary
cargo test                  # run all tests
cargo test <test_name>      # run a single test
make                        # same as cargo build --release
sudo make install           # install to /usr/local (does NOT rebuild)
```

## Usage

```bash
sdme rootfs import --name ubuntu - -f < rootfs.tar  # import a rootfs
sdme rootfs ls                                       # list imported rootfs
sdme create --name mybox --rootfs ubuntu             # create a container
sdme start mybox                                     # start it
sdme join mybox                                      # enter it (default: /bin/sh)
sdme join mybox /bin/bash -l                         # enter with a specific command
sdme logs mybox                                      # view logs
sdme logs mybox -f                                   # follow logs
sdme ps                                              # list containers
sdme stop mybox                                      # stop it
sdme rm mybox                                        # remove it (stops if running)
```
