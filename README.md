# sdme

Lightweight systemd-nspawn container manager with overlayfs.

sdme is a single static binary that creates, runs, and manages
systemd-booted containers on Linux. Each container gets an overlayfs
copy-on-write layer over a base root filesystem, so the base stays
untouched. No daemon, no runtime dependency beyond systemd. Containers
are regular systemd services with full init, journalctl, systemctl, and
cgroups.

See the [usage guide](docs/usage.md) for the full documentation. For
the backstory on how this project was built, see
[the story](docs/story.md).


## Install

Download a static binary from
[fiorix.github.io/sdme](https://fiorix.github.io/sdme/).

sdme requires root for all operations and systemd >= 252.

Install the one required dependency:

```bash
# Debian / Ubuntu
sudo apt install systemd-container

# Fedora / CentOS / AlmaLinux
sudo dnf install systemd-container

# Arch Linux
sudo pacman -S systemd    # systemd-nspawn is included

# openSUSE
sudo zypper install systemd-container
```

**On macOS?** See [macos.md](docs/macos.md) for instructions using
lima-vm.


## Quick start

The simplest thing sdme does is clone your running host system:

```bash
sudo sdme new
```

This creates an overlayfs clone of `/`, boots systemd inside a
container, and drops you into a root shell. Your host filesystem is
untouched -- all changes happen in the overlay.

Exit the container with `exit` or Ctrl+D, then manage it:

```bash
sudo sdme ps                # list containers and their status
sudo sdme stop <name>       # stop a container
sudo sdme start <name>      # start it again
sudo sdme join <name>       # re-enter a running container
sudo sdme rm <name>         # remove a container
```


## Importing root filesystems

Pull distro images from OCI registries:

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v
sudo sdme fs import fedora quay.io/fedora/fedora -v
```

Create containers from imported rootfs:

```bash
sudo sdme new -r ubuntu
sudo sdme new -r fedora
```

List and remove imported rootfs:

```bash
sudo sdme fs ls
sudo sdme fs rm <name>
```

sdme also imports from directories, tarballs, URLs, and QCOW2 disk
images. See the [usage guide](docs/usage.md) for details.


## OCI application images

Stock container images like nginx and redis run as systemd services
inside sdme containers. Import them on top of an existing base rootfs:

```bash
sudo sdme config set default_base_fs ubuntu
sudo sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v
sudo sdme new -r nginx
```

Inside the container, nginx is already running:

```bash
curl localhost
```

Since the default network mode is host, the service is also reachable
from the host.


## Networking

### Host network (default)

Containers share the host's network stack. Services bind directly to
host interfaces -- no port mapping needed.

### Private network with port forwarding

Isolate a container and expose specific ports:

```bash
sudo sdme create -r nginx --private-network --network-veth -p 8080:80 web
sudo sdme start web
curl http://localhost:8080
```

### Network zones

Containers in the same zone can reach each other by name:

```bash
sudo sdme create -r nginx --private-network --network-zone=myzone -p 8080:80 web
sudo sdme create -r ubuntu --private-network --network-zone=myzone client
sudo sdme start web client
sudo sdme exec client -- curl http://web
```

### Pods

A pod is a shared network namespace. Containers in a pod communicate
over localhost without port forwarding or bridges:

```bash
sudo sdme pod new demo
sudo sdme create --pod=demo -r nginx web
sudo sdme create --pod=demo -r redis cache
sudo sdme start web cache
```

Enter the pod to verify:

```bash
sudo sdme new --pod=demo -r ubuntu debug
# inside debug:
curl localhost           # reaches nginx
redis-cli 127.0.0.1     # reaches redis
```

Reach pod services from the host via nsenter:

```bash
sudo nsenter --net=/run/sdme/pods/demo/netns curl -s http://localhost
```

For a full multi-service example with prometheus, nginx, redis, and a
custom app, see the [pod tutorial](docs/tutorial-pods.md).


## Building root filesystems

Compose custom rootfs using a Dockerfile-like build config:

```
FROM ubuntu

RUN apt-get update && apt-get install -y prometheus
RUN systemctl enable prometheus
COPY prometheus.yml /etc/prometheus/prometheus.yml
```

Build it:

```bash
sudo sdme fs build prometheus prometheus.build -v
sudo sdme new -r prometheus
```

See the [usage guide](docs/usage.md) for the full build config
reference.


## Security

sdme supports three tiers of container hardening:

```bash
sudo sdme new -r ubuntu --hardened    # userns + private net + cap drops
sudo sdme new -r ubuntu --strict      # hardened + seccomp + AppArmor
```

Individual flags are also available: `--drop-capability`, `--capability`,
`--no-new-privileges`, `--read-only`, `--system-call-filter`, and
`--apparmor-profile`.

See [security.md](docs/security.md) for details.


## Further reading

- [docs/usage.md](docs/usage.md) -- Full user guide: install,
  lifecycle, rootfs management, networking, OCI, pods, and builds
- [docs/security.md](docs/security.md) -- Container isolation and
  security hardening
- [docs/oci.md](docs/oci.md) -- Running OCI container images with sdme
- [docs/architecture.md](docs/architecture.md) -- Architecture and
  design decisions
- [docs/hacks.md](docs/hacks.md) -- Wiring OCI apps into
  systemd-nspawn
- [docs/macos.md](docs/macos.md) -- Running sdme on macOS via lima-vm
- [docs/tests.md](docs/tests.md) -- Test suite overview
- [docs/tutorial-pods.md](docs/tutorial-pods.md) -- Multi-service pod
  tutorial with prometheus
- [docs/story.md](docs/story.md) -- The backstory and project stats
