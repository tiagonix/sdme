# Kubernetes Pod Support (Experimental)

sdme can run Kubernetes Pod YAML files as nspawn containers. Each pod maps to a single container where each workload runs as a separate systemd service chrooted into its own rootfs under `/oci/apps/{name}/root`.

## Quick Start

```bash
# Import a base rootfs (required once)
sudo sdme fs import docker.io/ubuntu:24.04 -n ubuntu

# Create and start a pod from a YAML file
sudo sdme kube apply -f my-pod.yaml --base-fs ubuntu

# Or create without starting
sudo sdme kube create -f my-pod.yaml --base-fs ubuntu
sudo sdme start my-pod

# Delete a pod (stops container, removes rootfs)
sudo sdme kube delete my-pod
```

## Supported YAML

Accepts `kind: Pod` (v1) and `kind: Deployment` (apps/v1, extracts the pod template).

### Example: Single Container

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

### Example: Multi-Container with Shared Volume

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web-cache
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
    volumeMounts:
    - name: shared-data
      mountPath: /usr/share/nginx/html
  - name: content-gen
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo '<h1>Hello from sdme</h1>' > /data/index.html && sleep infinity"]
    volumeMounts:
    - name: shared-data
      mountPath: /data
  volumes:
  - name: shared-data
    emptyDir: {}
```

### Example: Command Override

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: custom-cmd
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo 'hello world' && sleep infinity"]
```

## Supported Pod Spec Fields

| Field | Description |
|-------|-------------|
| `containers[].image` | OCI image reference (pulled from registry) |
| `containers[].name` | Container name (becomes service name) |
| `containers[].command` | Override ENTRYPOINT |
| `containers[].args` | Override CMD |
| `containers[].env` | Per-container environment variables |
| `containers[].ports` | Aggregated port forwarding (on private network) |
| `containers[].volumeMounts` | Bind volumes into the container's rootfs |
| `volumes` (emptyDir) | Shared directory between containers |
| `volumes` (hostPath) | Mount host directory into the pod |
| `restartPolicy` | Maps to systemd Restart= (Always/OnFailure/Never) |

## How It Works

1. **Parse & Validate** — reads the YAML, validates container names, volume references, etc.
2. **Pull Images** — downloads each container's OCI image from the registry
3. **Build Combined Rootfs** — copies the base rootfs, then places each container's OCI rootfs under `/oci/apps/{name}/root` with a generated systemd service unit
4. **Generate Volume Mounts** — if the pod has volume mounts, generates a `sdme-kube-volumes.service` oneshot unit that bind-mounts `/oci/volumes/{name}` into each app's root directory; app services depend on this unit via `After=`/`Requires=`
5. **Create Container** — creates an sdme container using the combined rootfs (hostPath volumes become nspawn `--bind=` mounts; emptyDir volumes live inside the rootfs)
6. **Start & Boot** — boots the container; the volume mount service runs first, then all app services start

### Filesystem Layout

```
/oci/
├── apps/
│   ├── nginx/
│   │   ├── root/           # nginx OCI rootfs
│   │   ├── env             # environment variables
│   │   ├── ports           # exposed ports
│   │   └── volumes         # declared volumes
│   └── redis/
│       ├── root/           # redis OCI rootfs
│       ├── env
│       ├── ports
│       └── volumes
└── volumes/
    └── cache-vol/          # emptyDir shared volume

/etc/systemd/system/
├── sdme-oci-nginx.service
├── sdme-oci-redis.service
├── sdme-kube-volumes.service    # oneshot: bind-mounts volumes
└── multi-user.target.wants/
    ├── sdme-oci-nginx.service -> ...
    ├── sdme-oci-redis.service -> ...
    └── sdme-kube-volumes.service -> ...
```

### Generated Service Units

Each container gets a systemd service `sdme-oci-{name}.service`:

```ini
[Unit]
Description=OCI app: nginx (docker.io/nginx:latest)
After=network.target
After=sdme-kube-volumes.service
Requires=sdme-kube-volumes.service

[Service]
Type=exec
RootDirectory=/oci/apps/nginx/root
MountAPIVFS=yes
Environment=LD_PRELOAD=/.sdme-devfd-shim.so
ExecStart=/docker-entrypoint.sh nginx -g 'daemon off;'
WorkingDirectory=/
EnvironmentFile=-/oci/apps/nginx/env
Restart=always

[Install]
WantedBy=multi-user.target
```

The `After=`/`Requires=` lines are only present when the pod has volume
mounts.

When shared volumes exist, a `sdme-kube-volumes.service` oneshot unit is
also generated:

```ini
[Unit]
Description=Kube volume mounts
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/mount --bind /oci/volumes/shared-data /oci/apps/nginx/root/usr/share/nginx/html
ExecStart=/bin/mount --bind /oci/volumes/shared-data /oci/apps/content-gen/root/data

[Install]
WantedBy=multi-user.target
```

This runs `mount --bind` in the container's PID 1 mount namespace before
app services start, so all services see the same shared directories.
Read-only mounts get an additional `remount,ro,bind` line.

## CLI Reference

```
sdme kube apply -f <file> [--base-fs NAME] [--timeout N]
sdme kube create -f <file> [--base-fs NAME]
sdme kube delete <name> [--force]
```

- `apply` — create + start + enter (like `sdme new`)
- `create` — create the container without starting
- `delete` — stop + remove container + remove rootfs

The `--base-fs` flag defaults to the `default_base_fs` config value.

## Viewing Logs

```bash
# View all container logs
sudo sdme logs my-pod

# View a specific service
sudo sdme exec my-pod -- journalctl -u sdme-oci-nginx.service -f
```

## State Management

Kube pods are tracked with additional state fields:

- `KUBE=yes` — marks this as a kube pod
- `KUBE_CONTAINERS=nginx,redis,...` — list of container names
- `KUBE_YAML_HASH={sha256}` — hash of the source YAML (for future update detection)

`sdme ps` shows kube pods with a KUBE column, e.g.: `kube:nginx,redis`

## Limitations

- No `initContainers` support yet
- No per-container resource limits (MemoryMax, CPUQuota)
- No per-container securityContext
- No configMap/secret volumes
- No probes (liveness, readiness, startup)
- No `sdme kube apply` update/re-apply (must delete and recreate)
- Only `emptyDir` and `hostPath` volume types are supported
