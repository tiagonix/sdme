# Tutorial: Multi-Service Pod with Prometheus

This tutorial builds a monitoring stack with prometheus, nginx, redis,
and a custom metrics app -- all sharing a network namespace via an sdme
pod. By the end you will have four containers communicating over
localhost inside the pod, with prometheus scraping metrics from all of
them.

## Prerequisites

- sdme installed and working (`sudo sdme new` boots a container)
- An imported Ubuntu rootfs (`sudo sdme fs import ubuntu docker.io/ubuntu:24.04 -v`)

Set ubuntu as the default base filesystem for OCI app imports:

```bash
sudo sdme config set default_base_fs ubuntu
```

## Import the OCI images

Import nginx and redis as OCI app images on top of the ubuntu base:

```bash
sudo sdme fs import nginx docker.io/nginx --base-fs=ubuntu -v
sudo sdme fs import redis docker.io/redis --base-fs=ubuntu -v
```

## Build a prometheus rootfs

Create a build config that installs prometheus on top of ubuntu.

Save this as `prometheus.build`:

```
FROM ubuntu

RUN apt-get update && apt-get install -y prometheus
RUN systemctl enable prometheus
```

Build the rootfs:

```bash
sudo sdme fs build prometheus prometheus.build -v
```

Verify your rootfs list:

```bash
sudo sdme fs ls
```

You should see `ubuntu`, `nginx`, `redis`, and `prometheus`.

## Create the pod

A pod is a shared network namespace. All containers joined to the pod
can reach each other on localhost.

```bash
sudo sdme pod new monitoring
```

## Create the containers

Create all four containers joined to the monitoring pod:

```bash
sudo sdme create --pod=monitoring -r nginx web
sudo sdme create --pod=monitoring -r redis cache
sudo sdme create --pod=monitoring -r prometheus monitor
sudo sdme create --pod=monitoring -r ubuntu app
```

## Configure prometheus

Create a prometheus configuration that scrapes all services in the pod.

Save this as `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: nginx
    metrics_path: /stub_status
    static_configs:
      - targets: ["localhost:80"]

  - job_name: app
    static_configs:
      - targets: ["localhost:9100"]
```

Bind-mount the config into the monitor container. Since the container
is already created, remove and recreate it with the bind mount:

```bash
sudo sdme rm monitor
sudo sdme create --pod=monitoring -r prometheus \
  -b "$(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml" monitor
```

## Set up the metrics app

The app container runs a minimal shell script that writes a counter to
redis and serves a `/metrics` endpoint for prometheus.

Create a script called `metrics-app.sh`:

```bash
#!/bin/bash
# Simple metrics app: increments a redis counter and exposes /metrics
COUNT=0
while true; do
    COUNT=$((COUNT + 1))
    # Write counter to redis
    echo "SET app_requests $COUNT" | nc -q1 127.0.0.1 6379 > /dev/null 2>&1
    # Serve metrics on port 9100
    RESPONSE="HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
    RESPONSE+="# HELP app_requests_total Total requests processed.\n"
    RESPONSE+="# TYPE app_requests_total counter\n"
    RESPONSE+="app_requests_total $COUNT\n"
    echo -e "$RESPONSE" | nc -l -p 9100 -q1 > /dev/null 2>&1
    sleep 1
done
```

Make it executable:

```bash
chmod +x metrics-app.sh
```

Remove and recreate the app container with the script bind-mounted:

```bash
sudo sdme rm app
sudo sdme create --pod=monitoring -r ubuntu \
  -b "$(pwd)/metrics-app.sh:/usr/local/bin/metrics-app.sh" app
```

## Start the containers

```bash
sudo sdme start web cache monitor app
```

Check that all containers are running:

```bash
sudo sdme ps
```

## Set up the metrics app service

Join the app container and create a systemd service for the script,
then install its dependencies:

```bash
sudo sdme exec app -- bash -c '
  apt-get update && apt-get install -y netcat-openbsd &&
  cat > /etc/systemd/system/metrics-app.service <<UNIT
[Unit]
Description=Metrics App
After=network.target

[Service]
ExecStart=/usr/local/bin/metrics-app.sh
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload &&
  systemctl enable --now metrics-app
'
```

## Verify the stack

### Check nginx from inside the pod

```bash
sudo nsenter --net=/run/sdme/pods/monitoring/netns \
  curl -s http://localhost
```

You should see the nginx welcome page.

### Check redis from inside the pod

```bash
sudo nsenter --net=/run/sdme/pods/monitoring/netns \
  bash -c 'echo PING | nc -q1 127.0.0.1 6379'
```

You should see `+PONG`.

### Check the metrics app

```bash
sudo nsenter --net=/run/sdme/pods/monitoring/netns \
  curl -s http://localhost:9100
```

You should see prometheus-format metrics with `app_requests_total`.

### Check prometheus

```bash
sudo nsenter --net=/run/sdme/pods/monitoring/netns \
  curl -s http://localhost:9090/api/v1/targets | python3 -m json.tool
```

This should show all three scrape targets (prometheus, nginx, app). The
prometheus and app targets should be "up". The nginx target may show as
"down" unless you enable the stub_status module -- that is fine for this
tutorial; the point is that prometheus can reach all endpoints over
localhost.

### Query a metric

```bash
sudo nsenter --net=/run/sdme/pods/monitoring/netns \
  curl -s 'http://localhost:9090/api/v1/query?query=app_requests_total'
```

## Cleanup

Stop and remove all containers, then remove the pod:

```bash
sudo sdme rm web cache monitor app
sudo sdme pod rm monitoring
```

Remove the build config and prometheus config if you no longer need them:

```bash
rm -f prometheus.build prometheus.yml metrics-app.sh
```

## What you learned

- **Pods** provide a shared network namespace where containers
  communicate over localhost without port forwarding or bridges.
- **OCI app imports** let you run stock container images (nginx, redis)
  as systemd services inside sdme containers.
- **Build configs** let you compose custom rootfs (prometheus) on top of
  any imported base.
- **Bind mounts** pass configuration and scripts into containers.
- **nsenter** lets you reach pod services from the host by entering the
  pod's network namespace.

For more on pods, networking, and OCI apps, see the
[usage guide](usage.md) and [OCI documentation](oci.md).
