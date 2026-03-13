# sdme

Lightweight systemd-nspawn container manager with overlayfs.

sdme is a single static binary that creates and manages Linux containers.
Each container boots full systemd (journalctl, systemctl, cgroups) over a
copy-on-write layer, keeping the base rootfs untouched. No daemon, no
runtime dependency beyond systemd.

## Quick start

Install the binary ([fiorix.github.io/sdme](https://fiorix.github.io/sdme/))
and the one required package (`sudo apt install systemd-container`), then
clone your running system into a throwaway container:

```bash
sudo sdme new
```

This creates an overlayfs clone of `/`, boots systemd inside it, and drops
you into a root shell. Install packages, change configs, break things. The
host is untouched. Exit the shell, then:

```bash
sudo sdme ps              # list containers and their status
sudo sdme stop <name>     # stop a container
sudo sdme join <name>     # re-enter a running container
sudo sdme rm <name>       # remove a container
```

## Install

Download a static binary from
[fiorix.github.io/sdme](https://fiorix.github.io/sdme/).

Requirements: root, Linux, systemd >= 252.

Install the one required dependency (`systemd-nspawn`, `machinectl`):

```bash
# Debian / Ubuntu
sudo apt install systemd-container

# Fedora / CentOS / AlmaLinux
sudo dnf install systemd-container

# Arch Linux
sudo pacman -S systemd   # systemd-nspawn is included

# openSUSE
sudo zypper install systemd-container
```

On macOS, see [docs/macos.md](docs/macos.md) for instructions using lima-vm.

## Any distro

Import root filesystems from OCI registries and run any distribution,
regardless of your host:

```bash
sudo sdme fs import debian docker.io/debian
sudo sdme fs import ubuntu docker.io/ubuntu:24.04
sudo sdme fs import fedora quay.io/fedora/fedora
sudo sdme fs import archlinux docker.io/archlinux
sudo sdme fs import suse docker.io/opensuse/tumbleweed
```

Each imported rootfs is a reusable template. Spin up as many containers as
you want from it; each gets its own overlayfs layer:

```bash
sudo sdme new -r ubuntu
sudo sdme new -r fedora
```

Other import sources: local directories, tarballs, URLs, QCOW2 cloud
images. See [docs/usage.md](docs/usage.md) for the full list.

## OCI applications

Any OCI image (nginx, redis, postgresql, anything on Docker Hub or any
registry) runs as a systemd service inside a booted container. No Docker
or Podman required.

```bash
sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v --install-packages=yes
sudo sdme fs import redis docker.io/redis --base-fs=ubuntu -v
sudo sdme new -r redis
```

Inside the container, the app is a managed systemd service:

```bash
systemctl status sdme-oci-redis.service
```

From outside, use `sdme logs` and `sdme exec`:

```bash
sudo sdme logs --oci <name>
sudo sdme exec --oci <name> redis-cli ping
```

See [OCI integration](docs/architecture.md#8-oci-integration) for the
full story.

## Pods

Pods give multiple containers a shared network namespace so they can
communicate via localhost:

```bash
sudo sdme pod new my-pod
sudo sdme create --pod=my-pod -r ubuntu db
sudo sdme create --pod=my-pod -r ubuntu app
sudo sdme start db app
```

Everything in `my-pod` shares the same loopback interface. Reach services
from the host with `nsenter`:

```bash
sudo nsenter --net=/run/sdme/pods/my-pod/netns curl -s http://localhost
```

See [docs/usage.md#pods](docs/usage.md#pods) for OCI pod groups and
advanced patterns.

## Kube pods

Run Kubernetes Pod YAML directly as nspawn containers:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
```

```bash
sudo sdme kube apply -f pod.yaml --base-fs ubuntu
```

Multi-container pods, shared volumes, init containers, secrets, and
configmaps are all supported. See [architecture.md](docs/architecture.md#11-kubernetes-pod-support) for
the full spec.

## Security

Three tiers of hardening:

```
Mechanism            Default   --hardened   --strict
-------------------  --------  -----------  ----------
User namespace       No        Yes          Yes
Private network      No        Yes          Yes
no_new_privs         No        Yes          Yes
Caps retained        26        23           14
Seccomp (extra)      None      None         4 deny groups
AppArmor             None      None         sdme-default
```

```bash
sudo sdme new -r ubuntu --hardened
sudo sdme new -r ubuntu --strict
```

Fine-grained controls: `--drop-capability`, `--capability`,
`--no-new-privileges`, `--read-only`, `--system-call-filter`,
`--apparmor-profile`. See [docs/security.md](docs/security.md) for
comparisons with Docker and Podman.

## Further reading

- [docs/usage.md](docs/usage.md): lifecycle, rootfs management,
  networking, OCI, pods, builds
- [docs/security.md](docs/security.md): isolation model and hardening
- [docs/architecture.md](docs/architecture.md): internals, design, OCI bridging, Kubernetes mapping
- [docs/macos.md](docs/macos.md): running sdme on macOS via lima-vm
- [test/README.md](test/README.md): test suite
- [test/results.md](test/results.md): latest test results
- [docs/story.md](docs/story.md): the backstory
