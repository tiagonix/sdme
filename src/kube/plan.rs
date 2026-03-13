//! Validated plan types, YAML parsing, and validation logic.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};

use super::types::*;
use crate::import::shell_join;
use crate::oci::registry::ImageReference;
use crate::validate_name;

// --- Parsed / validated plan ---

/// A validated plan for creating a kube pod container.
#[derive(Debug)]
pub(crate) struct KubePlan {
    pub(crate) pod_name: String,
    pub(crate) containers: Vec<KubeContainer>,
    pub(crate) init_containers: Vec<KubeContainer>,
    pub(crate) volumes: Vec<KubeVolume>,
    pub(crate) restart_policy: String,
    /// Aggregated ports from all containers.
    pub(crate) ports: Vec<ContainerPort>,
    /// Host-path binds needed at nspawn level.
    pub(crate) host_binds: Vec<(String, String)>,
    pub(crate) termination_grace_period: Option<u32>,
    pub(crate) run_as_user: Option<u32>,
    pub(crate) run_as_group: Option<u32>,
}

#[derive(Debug)]
pub(crate) struct KubeContainer {
    pub(crate) name: String,
    pub(crate) image: String,
    pub(crate) image_ref: ImageReference,
    pub(crate) command_override: Option<Vec<String>>,
    pub(crate) args_override: Option<Vec<String>>,
    pub(crate) env: Vec<(String, KubeEnvValue)>,
    pub(crate) volume_mounts: Vec<KubeVolumeMount>,
    pub(crate) working_dir_override: Option<String>,
    pub(crate) image_pull_policy: String,
    pub(crate) resource_lines: Vec<String>,
    pub(crate) readiness_exec: Option<String>,
    /// Parsed but not yet enforced at runtime (future: watchdog integration).
    #[allow(dead_code)]
    pub(crate) liveness_probe: Option<Probe>,
}

#[derive(Debug)]
pub(crate) struct KubeVolumeMount {
    pub(crate) volume_name: String,
    pub(crate) mount_path: String,
    // TODO: enforce read-only volume mounts (symlinks can't be read-only;
    // may need BindReadOnlyPaths or mount options in the future).
    #[allow(dead_code)]
    pub(crate) read_only: bool,
}

/// Resolved env var value (literal or deferred reference).
#[derive(Debug)]
pub(crate) enum KubeEnvValue {
    Literal(String),
    SecretKeyRef { name: String, key: String },
    ConfigMapKeyRef { name: String, key: String },
}

#[derive(Debug)]
pub(crate) enum KubeVolumeKind {
    EmptyDir,
    HostPath(String),
    Secret {
        secret_name: String,
        items: Vec<(String, String)>,
        default_mode: u32,
    },
    ConfigMap {
        configmap_name: String,
        items: Vec<(String, String)>,
        default_mode: u32,
    },
    Pvc(String),
}

#[derive(Debug)]
pub(crate) struct KubeVolume {
    pub(crate) name: String,
    pub(crate) kind: KubeVolumeKind,
}

// --- Known fields for unknown-field warnings ---

const KNOWN_POD_SPEC_FIELDS: &[&str] = &[
    "containers",
    "initContainers",
    "volumes",
    "restartPolicy",
    "terminationGracePeriodSeconds",
    "securityContext",
];

const KNOWN_CONTAINER_FIELDS: &[&str] = &[
    "name",
    "image",
    "command",
    "args",
    "env",
    "ports",
    "volumeMounts",
    "workingDir",
    "imagePullPolicy",
    "resources",
    "livenessProbe",
    "readinessProbe",
];

const KNOWN_SECURITY_CONTEXT_FIELDS: &[&str] = &["runAsUser", "runAsGroup", "runAsNonRoot"];

/// Walk raw YAML and warn about unrecognized fields.
fn warn_unknown_fields(raw: &serde_yml::Value, path: &str, known: &[&str]) {
    if let serde_yml::Value::Mapping(map) = raw {
        for (key, _val) in map {
            if let serde_yml::Value::String(k) = key {
                if !known.contains(&k.as_str()) {
                    eprintln!("warning: unknown field '{path}.{k}' will be ignored");
                }
            }
        }
    }
}

/// Warn about unknown fields in a pod spec value tree.
fn warn_pod_spec_unknown_fields(spec_value: &serde_yml::Value) {
    warn_unknown_fields(spec_value, "spec", KNOWN_POD_SPEC_FIELDS);

    if let serde_yml::Value::Mapping(map) = spec_value {
        // Check securityContext fields.
        if let Some(sc) = map.get(serde_yml::Value::String("securityContext".into())) {
            warn_unknown_fields(sc, "spec.securityContext", KNOWN_SECURITY_CONTEXT_FIELDS);
        }

        // Check container fields.
        for list_key in ["containers", "initContainers"] {
            if let Some(serde_yml::Value::Sequence(containers)) =
                map.get(serde_yml::Value::String(list_key.into()))
            {
                for (i, c) in containers.iter().enumerate() {
                    let fallback = format!("{i}");
                    let cname = c
                        .as_mapping()
                        .and_then(|m| m.get(serde_yml::Value::String("name".into())))
                        .and_then(|v| v.as_str())
                        .unwrap_or(&fallback);
                    warn_unknown_fields(
                        c,
                        &format!("spec.{list_key}[{cname}]"),
                        KNOWN_CONTAINER_FIELDS,
                    );
                }
            }
        }
    }
}

// --- Parsing ---

/// Parse a YAML file into a pod name and PodSpec.
pub(crate) fn parse_yaml(content: &str) -> Result<(String, PodSpec)> {
    let manifest: KubeManifest =
        serde_yml::from_str(content).context("failed to parse Kubernetes YAML")?;

    match manifest.kind.as_str() {
        "Pod" => {
            let name = manifest
                .metadata
                .as_ref()
                .and_then(|m| m.name.clone())
                .unwrap_or_default();
            let spec_value = manifest.spec.context("Pod manifest missing 'spec' field")?;
            warn_pod_spec_unknown_fields(&spec_value);
            let spec: PodSpec =
                serde_yml::from_value(spec_value).context("failed to parse Pod spec")?;
            Ok((name, spec))
        }
        "Deployment" => {
            let spec_value = manifest
                .spec
                .context("Deployment manifest missing 'spec' field")?;
            // For deployments, warn on the template spec inside.
            if let serde_yml::Value::Mapping(ref map) = spec_value {
                if let Some(serde_yml::Value::Mapping(ref tmap)) =
                    map.get(serde_yml::Value::String("template".into()))
                {
                    if let Some(tspec) = tmap.get(serde_yml::Value::String("spec".into())) {
                        warn_pod_spec_unknown_fields(tspec);
                    }
                }
            }
            let deploy_spec: DeploymentSpec =
                serde_yml::from_value(spec_value).context("failed to parse Deployment spec")?;
            let name = deploy_spec
                .template
                .metadata
                .as_ref()
                .and_then(|m| m.name.clone())
                .or_else(|| manifest.metadata.as_ref().and_then(|m| m.name.clone()))
                .unwrap_or_default();
            Ok((name, deploy_spec.template.spec))
        }
        other => bail!("unsupported kind: {other}; only Pod and Deployment are supported"),
    }
}

// --- Validation ---

/// Parse a K8s memory string (e.g. "128Mi", "1Gi", "1000") to a systemd-compatible string.
fn parse_k8s_memory(s: &str) -> Result<String> {
    for (suffix, unit) in [("Ki", "K"), ("Mi", "M"), ("Gi", "G"), ("Ti", "T")] {
        if let Some(num) = s.strip_suffix(suffix) {
            if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
                bail!("invalid memory value: {s}");
            }
            return Ok(format!("{num}{unit}"));
        }
    }
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
        // Plain bytes.
        Ok(s.to_string())
    } else {
        bail!("unsupported memory format: {s}")
    }
}

/// Parse a K8s CPU string (e.g. "500m", "2") to a CPUQuota percentage.
fn parse_k8s_cpu_quota(s: &str) -> Result<u32> {
    if let Some(prefix) = s.strip_suffix('m') {
        let millis: u32 = prefix
            .parse()
            .with_context(|| format!("invalid CPU millicore value: {s}"))?;
        Ok(millis / 10) // 1000m = 100%
    } else {
        let cores: f64 = s
            .parse()
            .with_context(|| format!("invalid CPU value: {s}"))?;
        Ok((cores * 100.0) as u32)
    }
}

/// Parse a K8s CPU request to a systemd CPUWeight (1-10000).
fn parse_k8s_cpu_weight(s: &str) -> Result<u32> {
    let millis = if let Some(prefix) = s.strip_suffix('m') {
        prefix
            .parse::<u32>()
            .with_context(|| format!("invalid CPU millicore value: {s}"))?
    } else {
        let cores: f64 = s
            .parse()
            .with_context(|| format!("invalid CPU value: {s}"))?;
        (cores * 1000.0) as u32
    };
    // Map millicores to weight: 100m = 100 (default), scale linearly, clamp to 1-10000.
    Ok(millis.clamp(1, 10000))
}

/// Build resource directive lines from a container's resources spec.
fn build_resource_lines(resources: &ResourceRequirements) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    if let Some(ref limits) = resources.limits {
        if let Some(ref mem) = limits.memory {
            let val = parse_k8s_memory(mem)?;
            lines.push(format!("MemoryMax={val}"));
        }
        if let Some(ref cpu) = limits.cpu {
            let pct = parse_k8s_cpu_quota(cpu)?;
            lines.push(format!("CPUQuota={pct}%"));
        }
    }
    if let Some(ref requests) = resources.requests {
        if let Some(ref mem) = requests.memory {
            let val = parse_k8s_memory(mem)?;
            lines.push(format!("MemoryLow={val}"));
        }
        if let Some(ref cpu) = requests.cpu {
            let weight = parse_k8s_cpu_weight(cpu)?;
            lines.push(format!("CPUWeight={weight}"));
        }
    }
    Ok(lines)
}

/// Build a readiness check ExecStartPost command from a readiness probe.
fn build_readiness_exec(probe: &Probe) -> Result<String> {
    let exec = probe
        .exec
        .as_ref()
        .context("only exec readiness probes are supported")?;
    if exec.command.is_empty() {
        bail!("readiness probe exec command is empty");
    }
    let initial_delay = probe.initial_delay_seconds.unwrap_or(0);
    let period = probe.period_seconds.unwrap_or(10);
    let threshold = probe.failure_threshold.unwrap_or(3);
    let cmd = shell_join(&exec.command);
    // The `-` prefix means systemd won't fail the unit if the check fails.
    Ok(format!(
        "-/bin/sh -c 'sleep {initial_delay}; for i in $(seq 1 {threshold}); do if {cmd}; then exit 0; fi; sleep {period}; done; exit 1'"
    ))
}

/// Validate a container and build a KubeContainer plan entry.
fn validate_container(c: Container) -> Result<KubeContainer> {
    let image_ref = ImageReference::parse(&c.image)
        .with_context(|| format!("invalid image reference: {}", c.image))?;
    let env: Vec<(String, KubeEnvValue)> = c
        .env
        .iter()
        .map(|e| {
            if let Some(ref vf) = e.value_from {
                if let Some(ref skr) = vf.secret_key_ref {
                    validate_name(&skr.name)
                        .with_context(|| format!("env '{}': invalid secret name", e.name))?;
                    Ok((
                        e.name.clone(),
                        KubeEnvValue::SecretKeyRef {
                            name: skr.name.clone(),
                            key: skr.key.clone(),
                        },
                    ))
                } else if let Some(ref cmkr) = vf.config_map_key_ref {
                    validate_name(&cmkr.name)
                        .with_context(|| format!("env '{}': invalid configmap name", e.name))?;
                    Ok((
                        e.name.clone(),
                        KubeEnvValue::ConfigMapKeyRef {
                            name: cmkr.name.clone(),
                            key: cmkr.key.clone(),
                        },
                    ))
                } else {
                    bail!(
                        "env '{}': valueFrom must specify secretKeyRef or configMapKeyRef",
                        e.name
                    )
                }
            } else {
                Ok((
                    e.name.clone(),
                    KubeEnvValue::Literal(e.value.clone().unwrap_or_default()),
                ))
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let volume_mounts: Vec<KubeVolumeMount> = c
        .volume_mounts
        .iter()
        .map(|vm| KubeVolumeMount {
            volume_name: vm.name.clone(),
            mount_path: vm.mount_path.clone(),
            read_only: vm.read_only,
        })
        .collect();

    // Validate imagePullPolicy.
    let image_pull_policy = match c.image_pull_policy.as_deref() {
        None | Some("Always") => "Always".to_string(),
        Some("IfNotPresent") => "IfNotPresent".to_string(),
        Some("Never") => "Never".to_string(),
        Some(other) => bail!(
            "container '{}': unsupported imagePullPolicy: {other}",
            c.name
        ),
    };

    // Validate workingDir.
    if let Some(ref wd) = c.working_dir {
        if !wd.starts_with('/') {
            bail!("container '{}': workingDir must be absolute: {wd}", c.name);
        }
        if wd.contains("..") {
            bail!(
                "container '{}': workingDir must not contain '..': {wd}",
                c.name
            );
        }
    }

    // Build resource lines.
    let resource_lines = if let Some(ref res) = c.resources {
        build_resource_lines(res)
            .with_context(|| format!("container '{}': invalid resources", c.name))?
    } else {
        Vec::new()
    };

    // Validate probes.
    if let Some(ref probe) = c.liveness_probe {
        if probe.exec.is_none() {
            bail!(
                "container '{}': only exec liveness probes are supported (httpGet/tcpSocket are not implemented)",
                c.name
            );
        }
    }
    let readiness_exec = if let Some(ref probe) = c.readiness_probe {
        Some(
            build_readiness_exec(probe)
                .with_context(|| format!("container '{}': invalid readiness probe", c.name))?,
        )
    } else {
        None
    };

    Ok(KubeContainer {
        name: c.name,
        image: c.image,
        image_ref,
        command_override: c.command,
        args_override: c.args,
        env,
        volume_mounts,
        working_dir_override: c.working_dir,
        image_pull_policy,
        resource_lines,
        readiness_exec,
        liveness_probe: c.liveness_probe,
    })
}

/// Validate a PodSpec and produce a KubePlan.
pub(crate) fn validate_and_plan(pod_name: &str, spec: PodSpec) -> Result<KubePlan> {
    if spec.containers.is_empty() {
        bail!("pod must have at least one container");
    }

    // Validate pod name.
    if pod_name.is_empty() {
        bail!("pod name is required (set metadata.name in the YAML)");
    }
    validate_name(pod_name).context("invalid pod name")?;

    // Validate container names are unique and valid (across both init and regular).
    let mut seen_names = HashSet::new();
    for c in spec.init_containers.iter().chain(spec.containers.iter()) {
        validate_name(&c.name).with_context(|| format!("invalid container name: {}", c.name))?;
        if !seen_names.insert(&c.name) {
            bail!("duplicate container name: {}", c.name);
        }
        if c.image.is_empty() {
            bail!("container '{}' has empty image", c.name);
        }
    }

    // Validate terminationGracePeriodSeconds.
    if let Some(t) = spec.termination_grace_period_seconds {
        if t == 0 {
            bail!("terminationGracePeriodSeconds must be > 0");
        }
    }

    // Validate securityContext.
    let (run_as_user, run_as_group) = if let Some(ref sc) = spec.security_context {
        if sc.run_as_non_root == Some(true) && sc.run_as_user.is_none() {
            bail!("securityContext.runAsNonRoot is true but runAsUser is not set");
        }
        if sc.run_as_non_root == Some(true) && sc.run_as_user == Some(0) {
            bail!("securityContext.runAsNonRoot is true but runAsUser is 0 (root)");
        }
        (sc.run_as_user, sc.run_as_group)
    } else {
        (None, None)
    };

    // Validate volume names are unique.
    let mut vol_names = HashSet::new();
    for v in &spec.volumes {
        if !vol_names.insert(&v.name) {
            bail!("duplicate volume name: {}", v.name);
        }
        // Validate hostPath.
        if let Some(ref hp) = v.host_path {
            if !hp.path.starts_with('/') {
                bail!(
                    "volume '{}' hostPath must be absolute, got: {}",
                    v.name,
                    hp.path
                );
            }
            if hp.path.contains("..") {
                bail!(
                    "volume '{}' hostPath must not contain '..': {}",
                    v.name,
                    hp.path
                );
            }
        }
    }

    // Validate volume mount references (across both init and regular containers).
    for c in spec.init_containers.iter().chain(spec.containers.iter()) {
        for vm in &c.volume_mounts {
            if !vol_names.contains(&vm.name) {
                bail!(
                    "container '{}' references undefined volume: {}",
                    c.name,
                    vm.name
                );
            }
            if !vm.mount_path.starts_with('/') {
                bail!(
                    "container '{}' volumeMount path must be absolute: {}",
                    c.name,
                    vm.mount_path
                );
            }
            if vm.mount_path.contains("..") {
                bail!(
                    "container '{}' volumeMount path must not contain '..': {}",
                    c.name,
                    vm.mount_path
                );
            }
        }
    }

    // Parse restart policy.
    let restart_policy = match spec.restart_policy.as_deref() {
        None | Some("Always") => "always".to_string(),
        Some("OnFailure") => "on-failure".to_string(),
        Some("Never") => "no".to_string(),
        Some(other) => bail!("unsupported restartPolicy: {other}"),
    };

    // Build volumes.
    let volumes: Vec<KubeVolume> = spec
        .volumes
        .iter()
        .map(|v| {
            let kind = if let Some(ref hp) = v.host_path {
                KubeVolumeKind::HostPath(hp.path.clone())
            } else if let Some(ref sec) = v.secret {
                validate_name(&sec.secret_name)
                    .with_context(|| format!("volume '{}': invalid secret name", v.name))?;
                let items: Vec<(String, String)> = sec
                    .items
                    .iter()
                    .map(|item| {
                        if item.path.contains("..") {
                            bail!(
                                "volume '{}': secret item path must not contain '..': {}",
                                v.name,
                                item.path
                            );
                        }
                        if item.path.starts_with('/') {
                            bail!(
                                "volume '{}': secret item path must not start with '/': {}",
                                v.name,
                                item.path
                            );
                        }
                        Ok((item.key.clone(), item.path.clone()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                KubeVolumeKind::Secret {
                    secret_name: sec.secret_name.clone(),
                    items,
                    default_mode: sec.default_mode,
                }
            } else if let Some(ref cm) = v.config_map {
                validate_name(&cm.name)
                    .with_context(|| format!("volume '{}': invalid configmap name", v.name))?;
                let items: Vec<(String, String)> = cm
                    .items
                    .iter()
                    .map(|item| {
                        if item.path.contains("..") {
                            bail!(
                                "volume '{}': configmap item path must not contain '..': {}",
                                v.name,
                                item.path
                            );
                        }
                        if item.path.starts_with('/') {
                            bail!(
                                "volume '{}': configmap item path must not start with '/': {}",
                                v.name,
                                item.path
                            );
                        }
                        Ok((item.key.clone(), item.path.clone()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                KubeVolumeKind::ConfigMap {
                    configmap_name: cm.name.clone(),
                    items,
                    default_mode: cm.default_mode,
                }
            } else if let Some(ref pvc) = v.persistent_volume_claim {
                validate_name(&pvc.claim_name)
                    .with_context(|| format!("volume '{}': invalid PVC claim name", v.name))?;
                KubeVolumeKind::Pvc(pvc.claim_name.clone())
            } else {
                KubeVolumeKind::EmptyDir
            };
            Ok(KubeVolume {
                name: v.name.clone(),
                kind,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Collect nspawn --bind= arguments for hostPath volumes only.
    // emptyDir volumes live inside the rootfs at /oci/volumes/{name} and are
    // bind-mounted to each app's root via sdme-kube-volumes.service.
    // ConfigMap and Secret volumes are populated into the rootfs.
    // PVC volumes get host_binds added in kube_create after datadir is known.
    let host_binds: Vec<(String, String)> = volumes
        .iter()
        .filter_map(|v| match &v.kind {
            KubeVolumeKind::HostPath(path) => {
                Some((path.clone(), format!("/oci/volumes/{}", v.name)))
            }
            KubeVolumeKind::EmptyDir
            | KubeVolumeKind::Secret { .. }
            | KubeVolumeKind::ConfigMap { .. }
            | KubeVolumeKind::Pvc(_) => None,
        })
        .collect();

    // Aggregate ports from all containers, warn on duplicates.
    let mut ports = Vec::new();
    let mut seen_ports = HashSet::new();
    for c in &spec.containers {
        for p in &c.ports {
            if !seen_ports.insert(p.container_port) {
                eprintln!(
                    "warning: duplicate port {} in container '{}', skipping",
                    p.container_port, c.name
                );
                continue;
            }
            ports.push(p.clone());
        }
    }

    // Build init container plans.
    let init_containers: Vec<KubeContainer> = spec
        .init_containers
        .into_iter()
        .map(validate_container)
        .collect::<Result<Vec<_>>>()?;

    // Build container plans.
    let containers: Vec<KubeContainer> = spec
        .containers
        .into_iter()
        .map(validate_container)
        .collect::<Result<Vec<_>>>()?;

    Ok(KubePlan {
        pod_name: pod_name.to_string(),
        containers,
        init_containers,
        volumes,
        restart_policy,
        ports,
        host_binds,
        termination_grace_period: spec.termination_grace_period_seconds,
        run_as_user,
        run_as_group,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDataDir;
    use std::fs;
    use std::sync::Mutex;

    #[test]
    fn test_parse_simple_pod() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
spec:
  containers:
  - name: nginx
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(name, "nginx-pod");
        assert_eq!(spec.containers.len(), 1);
        assert_eq!(spec.containers[0].name, "nginx");
        assert_eq!(spec.containers[0].image, "docker.io/nginx:latest");
        assert_eq!(spec.containers[0].ports.len(), 1);
        assert_eq!(spec.containers[0].ports[0].container_port, 80);
    }

    #[test]
    fn test_parse_multi_container_pod() {
        let yaml = r#"
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
    - name: cache-vol
      mountPath: /var/cache
  - name: redis
    image: docker.io/redis:latest
    ports:
    - containerPort: 6379
    volumeMounts:
    - name: cache-vol
      mountPath: /data
  volumes:
  - name: cache-vol
    emptyDir: {}
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(name, "web-cache");
        assert_eq!(spec.containers.len(), 2);
        assert_eq!(spec.containers[0].name, "nginx");
        assert_eq!(spec.containers[1].name, "redis");
        assert_eq!(spec.volumes.len(), 1);
        assert_eq!(spec.volumes[0].name, "cache-vol");
        assert!(spec.volumes[0].empty_dir.is_some());
    }

    #[test]
    fn test_parse_deployment() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      name: my-pod
    spec:
      containers:
      - name: web
        image: docker.io/nginx:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(name, "my-pod");
        assert_eq!(spec.containers.len(), 1);
        assert_eq!(spec.containers[0].name, "web");
    }

    #[test]
    fn test_parse_deployment_name_fallback() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    spec:
      containers:
      - name: web
        image: docker.io/nginx:latest
"#;
        let (name, _) = parse_yaml(yaml).unwrap();
        assert_eq!(name, "my-deploy");
    }

    #[test]
    fn test_parse_invalid_kind() {
        let yaml = r#"
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: my-sts
spec:
  containers:
  - name: web
    image: docker.io/nginx:latest
"#;
        let err = parse_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("unsupported kind: StatefulSet"));
    }

    #[test]
    fn test_parse_env_vars() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: env-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    env:
    - name: FOO
      value: bar
    - name: BAZ
      value: "123"
"#;
        let (_, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(spec.containers[0].env.len(), 2);
        assert_eq!(spec.containers[0].env[0].name, "FOO");
        assert_eq!(spec.containers[0].env[0].value, Some("bar".to_string()));
    }

    #[test]
    fn test_parse_volumes() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: vol-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: data
      mountPath: /data
    - name: host-config
      mountPath: /etc/app
      readOnly: true
  volumes:
  - name: data
    emptyDir: {}
  - name: host-config
    hostPath:
      path: /opt/config
"#;
        let (_, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(spec.volumes.len(), 2);
        assert!(spec.volumes[0].empty_dir.is_some());
        assert!(spec.volumes[0].host_path.is_none());
        assert!(spec.volumes[1].empty_dir.is_none());
        assert_eq!(
            spec.volumes[1].host_path.as_ref().unwrap().path,
            "/opt/config"
        );
        assert!(spec.containers[0].volume_mounts[1].read_only);
    }

    #[test]
    fn test_parse_volume_mount_validation() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: bad-vol
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: nonexistent
      mountPath: /data
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("undefined volume"));
    }

    #[test]
    fn test_parse_command_args_override() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cmd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo hello"]
"#;
        let (_, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(
            spec.containers[0].command,
            Some(vec!["/bin/sh".to_string(), "-c".to_string()])
        );
        assert_eq!(
            spec.containers[0].args,
            Some(vec!["echo hello".to_string()])
        );
    }

    #[test]
    fn test_parse_restart_policy() {
        for (policy, expected) in [
            ("Always", "always"),
            ("OnFailure", "on-failure"),
            ("Never", "no"),
        ] {
            let yaml = format!(
                r#"
apiVersion: v1
kind: Pod
metadata:
  name: restart-pod
spec:
  restartPolicy: {policy}
  containers:
  - name: app
    image: docker.io/busybox:latest
"#
            );
            let (name, spec) = parse_yaml(&yaml).unwrap();
            let plan = validate_and_plan(&name, spec).unwrap();
            assert_eq!(plan.restart_policy, expected, "policy={policy}");
        }
    }

    #[test]
    fn test_port_aggregation() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: multi-port
spec:
  containers:
  - name: web
    image: docker.io/nginx:latest
    ports:
    - containerPort: 80
    - containerPort: 443
  - name: api
    image: docker.io/node:latest
    ports:
    - containerPort: 3000
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.ports.len(), 3);
        let port_nums: Vec<u16> = plan.ports.iter().map(|p| p.container_port).collect();
        assert!(port_nums.contains(&80));
        assert!(port_nums.contains(&443));
        assert!(port_nums.contains(&3000));
    }

    #[test]
    fn test_validate_empty_containers() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: empty-pod
spec:
  containers: []
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("at least one container"));
    }

    #[test]
    fn test_validate_duplicate_container_names() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: dup-pod
spec:
  containers:
  - name: app
    image: docker.io/nginx:latest
  - name: app
    image: docker.io/redis:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("duplicate container name"));
    }

    #[test]
    fn test_validate_hostpath_relative() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: bad-host
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: data
    hostPath:
      path: relative/path
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn test_validate_hostpath_dotdot() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: bad-host2
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: data
    hostPath:
      path: /tmp/../etc
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn test_default_restart_policy() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: default-restart
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.restart_policy, "always");
    }

    // --- Feature 1: Unknown fields ---

    #[test]
    fn test_unknown_fields_parse_ok() {
        // Unknown fields should not cause parse errors.
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: warn-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      exec:
        command: ["true"]
    securityContext:
      runAsUser: 1000
    unknownField: "hello"
"#;
        let result = parse_yaml(yaml);
        assert!(result.is_ok(), "parse should succeed with unknown fields");
    }

    // --- Feature 2: imagePullPolicy ---

    #[test]
    fn test_image_pull_policy_parse() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pull-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    imagePullPolicy: IfNotPresent
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.containers[0].image_pull_policy, "IfNotPresent");
    }

    #[test]
    fn test_image_pull_policy_default() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pull-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.containers[0].image_pull_policy, "Always");
    }

    #[test]
    fn test_image_pull_policy_invalid() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pull-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    imagePullPolicy: Bogus
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("unsupported imagePullPolicy"));
    }

    // --- Feature 3: terminationGracePeriodSeconds ---

    #[test]
    fn test_termination_grace_period() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: grace-pod
spec:
  terminationGracePeriodSeconds: 45
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.termination_grace_period, Some(45));
    }

    #[test]
    fn test_termination_grace_period_zero() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: grace-pod
spec:
  terminationGracePeriodSeconds: 0
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("must be > 0"));
    }

    // --- Feature 4: workingDir ---

    #[test]
    fn test_working_dir() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: wd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: /app
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(
            plan.containers[0].working_dir_override,
            Some("/app".to_string())
        );
    }

    #[test]
    fn test_working_dir_relative_rejected() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: wd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: relative/path
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("workingDir must be absolute"));
    }

    #[test]
    fn test_working_dir_dotdot_rejected() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: wd-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: /app/../etc
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("must not contain '..'"));
    }

    // --- Feature 5: resources ---

    #[test]
    fn test_resource_limits_memory() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      limits:
        memory: 256Mi
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0]
            .resource_lines
            .contains(&"MemoryMax=256M".to_string()));
    }

    #[test]
    fn test_resource_limits_cpu() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      limits:
        cpu: "2"
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0]
            .resource_lines
            .contains(&"CPUQuota=200%".to_string()));
    }

    #[test]
    fn test_resource_limits_cpu_millicore() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      limits:
        cpu: 500m
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0]
            .resource_lines
            .contains(&"CPUQuota=50%".to_string()));
    }

    #[test]
    fn test_resource_requests() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: res-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    resources:
      requests:
        memory: 128Mi
        cpu: 250m
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0]
            .resource_lines
            .contains(&"MemoryLow=128M".to_string()));
        assert!(plan.containers[0]
            .resource_lines
            .contains(&"CPUWeight=250".to_string()));
    }

    #[test]
    fn test_parse_k8s_memory_formats() {
        assert_eq!(parse_k8s_memory("128Ki").unwrap(), "128K");
        assert_eq!(parse_k8s_memory("256Mi").unwrap(), "256M");
        assert_eq!(parse_k8s_memory("1Gi").unwrap(), "1G");
        assert_eq!(parse_k8s_memory("2Ti").unwrap(), "2T");
        assert_eq!(parse_k8s_memory("1048576").unwrap(), "1048576");
        assert!(parse_k8s_memory("10MB").is_err());
    }

    #[test]
    fn test_parse_k8s_cpu_quota() {
        assert_eq!(parse_k8s_cpu_quota("1000m").unwrap(), 100);
        assert_eq!(parse_k8s_cpu_quota("500m").unwrap(), 50);
        assert_eq!(parse_k8s_cpu_quota("250m").unwrap(), 25);
        assert_eq!(parse_k8s_cpu_quota("2").unwrap(), 200);
        assert_eq!(parse_k8s_cpu_quota("0.5").unwrap(), 50);
    }

    // --- Feature 6: securityContext ---

    #[test]
    fn test_security_context_run_as_user() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.run_as_user, Some(1000));
        assert_eq!(plan.run_as_group, Some(1000));
    }

    #[test]
    fn test_security_context_run_as_non_root_without_user() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("runAsNonRoot is true"));
    }

    #[test]
    fn test_security_context_run_as_non_root_with_root_user() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: sec-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 0
  containers:
  - name: app
    image: docker.io/busybox:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("runAsUser is 0"));
    }

    // --- Feature 7: initContainers ---

    #[test]
    fn test_init_containers() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
spec:
  initContainers:
  - name: init-setup
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo init"]
  containers:
  - name: app
    image: docker.io/nginx:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert_eq!(spec.init_containers.len(), 1);
        assert_eq!(spec.init_containers[0].name, "init-setup");
        let plan = validate_and_plan(&name, spec).unwrap();
        assert_eq!(plan.init_containers.len(), 1);
        assert_eq!(plan.init_containers[0].name, "init-setup");
        assert_eq!(plan.containers.len(), 1);
        assert_eq!(plan.containers[0].name, "app");
    }

    #[test]
    fn test_init_container_duplicate_name() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
spec:
  initContainers:
  - name: app
    image: docker.io/busybox:latest
  containers:
  - name: app
    image: docker.io/nginx:latest
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("duplicate container name"));
    }

    // --- Feature 8: Probes ---

    #[test]
    fn test_readiness_probe_exec() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    readinessProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/ready"]
      initialDelaySeconds: 5
      periodSeconds: 3
      failureThreshold: 5
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        let exec = plan.containers[0].readiness_exec.as_ref().unwrap();
        assert!(exec.contains("sleep 5"));
        assert!(exec.contains("seq 1 5"));
        assert!(exec.contains("sleep 3"));
        assert!(exec.contains("test -f /tmp/ready"));
    }

    #[test]
    fn test_liveness_probe_non_exec_rejected() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      initialDelaySeconds: 5
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains("only exec liveness probes"));
    }

    #[test]
    fn test_liveness_probe_exec_ok() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: probe-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    livenessProbe:
      exec:
        command: ["true"]
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(plan.containers[0].liveness_probe.is_some());
    }

    // --- Combined feature test ---

    #[test]
    fn test_all_features_combined() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: full-pod
spec:
  terminationGracePeriodSeconds: 30
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
  initContainers:
  - name: init-setup
    image: docker.io/busybox:latest
    command: ["/bin/sh", "-c"]
    args: ["echo init"]
  containers:
  - name: app
    image: docker.io/busybox:latest
    workingDir: /app
    imagePullPolicy: IfNotPresent
    resources:
      limits:
        memory: 256Mi
        cpu: "1"
      requests:
        memory: 128Mi
        cpu: 250m
    readinessProbe:
      exec:
        command: ["/bin/sh", "-c", "test -f /tmp/ready"]
    volumeMounts:
    - name: shared
      mountPath: /data
  volumes:
  - name: shared
    emptyDir: {}
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();

        assert_eq!(plan.termination_grace_period, Some(30));
        assert_eq!(plan.run_as_user, Some(1000));
        assert_eq!(plan.run_as_group, Some(1000));
        assert_eq!(plan.init_containers.len(), 1);
        assert_eq!(plan.containers.len(), 1);

        let app = &plan.containers[0];
        assert_eq!(app.working_dir_override, Some("/app".to_string()));
        assert_eq!(app.image_pull_policy, "IfNotPresent");
        assert!(app.resource_lines.contains(&"MemoryMax=256M".to_string()));
        assert!(app.resource_lines.contains(&"CPUQuota=100%".to_string()));
        assert!(app.resource_lines.contains(&"MemoryLow=128M".to_string()));
        assert!(app.resource_lines.contains(&"CPUWeight=250".to_string()));
        assert!(app.readiness_exec.is_some());
    }

    // --- Unit file integration tests ---
    //
    // These tests call `setup_kube_container()` with a temp directory and
    // verify the generated systemd unit file contains correct directives.

    static UNIT_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: set up a temp dir, call `setup_kube_container()`, return the
    /// generated unit file content.
    fn setup_test_container(
        name: &str,
        kc: &KubeContainer,
        plan: &KubePlan,
        is_init: bool,
        init_container_names: &[String],
    ) -> String {
        let tmp = TempDataDir::new("kube-unit");
        let staging = tmp.path().join("staging");
        let app_dir = staging.join(format!("oci/apps/{name}"));
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root).unwrap();
        fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

        super::super::create::setup_kube_container(
            tmp.path(),
            &staging,
            &app_dir,
            kc,
            None,
            &plan.restart_policy,
            &plan.volumes,
            plan,
            is_init,
            init_container_names,
            false,
        )
        .unwrap();

        let unit_path = staging.join(format!("etc/systemd/system/sdme-oci-{name}.service"));
        fs::read_to_string(&unit_path).unwrap()
    }

    fn make_test_container(name: &str) -> KubeContainer {
        KubeContainer {
            name: name.to_string(),
            image: "docker.io/busybox:latest".to_string(),
            image_ref: ImageReference::parse("docker.io/busybox:latest").unwrap(),
            command_override: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
            args_override: Some(vec!["echo hello".to_string()]),
            env: vec![],
            volume_mounts: vec![],
            working_dir_override: None,
            image_pull_policy: "Always".to_string(),
            resource_lines: vec![],
            readiness_exec: None,
            liveness_probe: None,
        }
    }

    fn make_test_plan() -> KubePlan {
        KubePlan {
            pod_name: "test-pod".to_string(),
            containers: vec![],
            init_containers: vec![],
            volumes: vec![],
            restart_policy: "always".to_string(),
            ports: vec![],
            host_binds: vec![],
            termination_grace_period: None,
            run_as_user: None,
            run_as_group: None,
        }
    }

    #[test]
    fn test_unit_default_container() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("app");
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        assert!(unit.contains("Type=exec"), "default type should be exec");
        assert!(
            unit.contains("Restart=always"),
            "should have restart policy"
        );
        assert!(
            !unit.contains("RemainAfterExit"),
            "should not have RemainAfterExit"
        );
        assert!(
            !unit.contains("TimeoutStopSec"),
            "should not have TimeoutStopSec"
        );
        assert!(
            unit.contains("After=network.target\n"),
            "should have After=network.target only"
        );
        assert!(
            !unit.contains("Requires="),
            "should not have Requires= line"
        );
    }

    #[test]
    fn test_unit_init_container_type() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("init-setup");
        let plan = make_test_plan();
        let unit = setup_test_container("init-setup", &kc, &plan, true, &[]);

        assert!(
            unit.contains("Type=oneshot"),
            "init container should be oneshot"
        );
        assert!(
            unit.contains("RemainAfterExit=yes"),
            "init container should have RemainAfterExit"
        );
        assert!(
            !unit.contains("Restart="),
            "oneshot init container should not have Restart="
        );
    }

    #[test]
    fn test_unit_main_container_deps() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("app");
        let plan = make_test_plan();
        let init_names = vec!["init-setup".to_string()];
        let unit = setup_test_container("app", &kc, &plan, false, &init_names);

        assert!(
            unit.contains("After=network.target sdme-oci-init-setup.service"),
            "should depend on init container, got: {unit}"
        );
        assert!(
            unit.contains("Requires=sdme-oci-init-setup.service"),
            "should require init container"
        );
    }

    #[test]
    fn test_unit_termination_grace_period() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("app");
        let mut plan = make_test_plan();
        plan.termination_grace_period = Some(45);
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        assert!(
            unit.contains("TimeoutStopSec=45s"),
            "should have TimeoutStopSec=45s"
        );
    }

    #[test]
    fn test_unit_working_dir_override() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.working_dir_override = Some("/app".to_string());
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        // In isolate mode, working dir is passed as an argument to .sdme-isolate,
        // not as a systemd WorkingDirectory= directive.
        assert!(
            unit.contains("/.sdme-isolate 0 0 /app"),
            "should have /app as working dir in isolate exec, got: {unit}"
        );
    }

    #[test]
    fn test_unit_resources() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.resource_lines = vec!["MemoryMax=256M".to_string(), "CPUQuota=100%".to_string()];
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        assert!(unit.contains("MemoryMax=256M"), "should have MemoryMax");
        assert!(unit.contains("CPUQuota=100%"), "should have CPUQuota");
    }

    #[test]
    fn test_unit_readiness_probe() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let mut kc = make_test_container("app");
        kc.readiness_exec = Some("/bin/sh -c 'test -f /tmp/ready'".to_string());
        let plan = make_test_plan();
        let unit = setup_test_container("app", &kc, &plan, false, &[]);

        assert!(
            unit.contains("ExecStartPost=/bin/sh -c 'test -f /tmp/ready'"),
            "should have ExecStartPost for readiness probe"
        );
    }

    #[test]
    fn test_unit_security_context_user() {
        let _lock = UNIT_TEST_LOCK.lock().unwrap();
        let kc = make_test_container("app");
        let mut plan = make_test_plan();
        plan.run_as_user = Some(1000);
        plan.run_as_group = Some(1000);

        // setup_kube_container passes "1000:1000" as user, which
        // resolve_oci_user() resolves as numeric UID:GID. Kube uses
        // isolate mode so .sdme-isolate is deployed. Numeric UIDs
        // work without etc/passwd.
        let tmp = TempDataDir::new("kube-unit-sec");
        let staging = tmp.path().join("staging");
        let app_dir = staging.join("oci/apps/app");
        let app_root = app_dir.join("root");
        fs::create_dir_all(&app_root).unwrap();
        fs::create_dir_all(staging.join("etc/systemd/system/multi-user.target.wants")).unwrap();

        super::super::create::setup_kube_container(
            tmp.path(),
            &staging,
            &app_dir,
            &kc,
            None,
            &plan.restart_policy,
            &plan.volumes,
            &plan,
            false,
            &[],
            false,
        )
        .unwrap();

        let unit_path = staging.join("etc/systemd/system/sdme-oci-app.service");
        let unit = fs::read_to_string(&unit_path).unwrap();

        // Kube uses isolate mode: should use .sdme-isolate with uid/gid.
        assert!(
            unit.contains("/.sdme-isolate 1000 1000"),
            "should use isolate with uid=1000 gid=1000, got: {unit}"
        );
        // isolate binary should be deployed.
        assert!(app_root.join(".sdme-isolate").is_file());
    }

    // --- Secret volumes ---

    #[test]
    fn test_parse_secret_volume() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-secret
      mountPath: /etc/secrets
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert!(spec.volumes[0].secret.is_some());
        let secret = spec.volumes[0].secret.as_ref().unwrap();
        assert_eq!(secret.secret_name, "db-creds");
        assert!(secret.items.is_empty());
        assert_eq!(secret.default_mode, 0o644);

        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(
            plan.volumes[0].kind,
            KubeVolumeKind::Secret { .. }
        ));
        // Secret volumes should not generate host binds.
        assert!(plan.host_binds.is_empty());
    }

    #[test]
    fn test_parse_secret_volume_with_items() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-secret
      mountPath: /etc/secrets
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      items:
      - key: username
        path: user.txt
      - key: password
        path: pass.txt
      defaultMode: 256
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        if let KubeVolumeKind::Secret {
            ref items,
            default_mode,
            ..
        } = plan.volumes[0].kind
        {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0], ("username".to_string(), "user.txt".to_string()));
            assert_eq!(items[1], ("password".to_string(), "pass.txt".to_string()));
            assert_eq!(default_mode, 256); // 0o400
        } else {
            panic!("expected Secret volume kind");
        }
    }

    #[test]
    fn test_secret_volume_invalid_name() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-secret
    secret:
      secretName: INVALID
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("invalid secret name")
                || err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_secret_volume_item_path_traversal() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      items:
      - key: username
        path: ../etc/passwd
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(err.to_string().contains(".."), "unexpected error: {err}");
    }

    #[test]
    fn test_secret_volume_item_path_absolute() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      items:
      - key: username
        path: /etc/passwd
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("must not start with '/'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_secret_volume_octal_string_mode() {
        // YAML 1.2 treats `0400` as a string; verify the custom deserializer
        // handles it by parsing it as octal.
        let yaml = "
apiVersion: v1
kind: Pod
metadata:
  name: secret-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-secret
      mountPath: /etc/secrets
  volumes:
  - name: my-secret
    secret:
      secretName: db-creds
      defaultMode: \"0400\"
";
        let (_name, spec) = parse_yaml(yaml).unwrap();
        let secret = spec.volumes[0].secret.as_ref().unwrap();
        assert_eq!(secret.default_mode, 0o400); // 256 decimal
    }

    // --- ConfigMap volumes ---

    #[test]
    fn test_parse_configmap_volume() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cm-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-config
      mountPath: /etc/config
  volumes:
  - name: my-config
    configMap:
      name: app-config
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert!(spec.volumes[0].config_map.is_some());
        let cm = spec.volumes[0].config_map.as_ref().unwrap();
        assert_eq!(cm.name, "app-config");
        assert!(cm.items.is_empty());
        assert_eq!(cm.default_mode, 0o644);

        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(
            plan.volumes[0].kind,
            KubeVolumeKind::ConfigMap { .. }
        ));
        // ConfigMap volumes should not generate host binds.
        assert!(plan.host_binds.is_empty());
    }

    #[test]
    fn test_parse_configmap_volume_with_items() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cm-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: my-config
      mountPath: /etc/config
  volumes:
  - name: my-config
    configMap:
      name: app-config
      items:
      - key: config-key
        path: app.conf
      - key: log-key
        path: log.conf
      defaultMode: 256
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        if let KubeVolumeKind::ConfigMap {
            ref items,
            default_mode,
            ..
        } = plan.volumes[0].kind
        {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0], ("config-key".to_string(), "app.conf".to_string()));
            assert_eq!(items[1], ("log-key".to_string(), "log.conf".to_string()));
            assert_eq!(default_mode, 256); // 0o400
        } else {
            panic!("expected ConfigMap volume kind");
        }
    }

    #[test]
    fn test_configmap_volume_invalid_name() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: cm-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: my-config
    configMap:
      name: INVALID
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("invalid configmap name")
                || err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    // --- PVC volumes ---

    #[test]
    fn test_parse_pvc_volume() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pvc-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    volumeMounts:
    - name: data-volume
      mountPath: /data
  volumes:
  - name: data-volume
    persistentVolumeClaim:
      claimName: test-data
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        assert!(spec.volumes[0].persistent_volume_claim.is_some());
        let pvc = spec.volumes[0].persistent_volume_claim.as_ref().unwrap();
        assert_eq!(pvc.claim_name, "test-data");

        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(plan.volumes[0].kind, KubeVolumeKind::Pvc(_)));
        // PVC volumes don't generate host binds at plan time (added in kube_create).
        assert!(plan.host_binds.is_empty());
    }

    #[test]
    fn test_pvc_volume_invalid_name() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: pvc-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
  volumes:
  - name: data-volume
    persistentVolumeClaim:
      claimName: INVALID
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string().contains("invalid PVC claim name")
                || err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    // --- env valueFrom ---

    #[test]
    fn test_parse_env_value_from_secret() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: env-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-creds
          key: password
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(
            plan.containers[0].env[0].1,
            KubeEnvValue::SecretKeyRef { .. }
        ));
        if let KubeEnvValue::SecretKeyRef { ref name, ref key } = plan.containers[0].env[0].1 {
            assert_eq!(name, "db-creds");
            assert_eq!(key, "password");
        }
    }

    #[test]
    fn test_parse_env_value_from_configmap() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: env-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    env:
    - name: LOG_LEVEL
      valueFrom:
        configMapKeyRef:
          name: app-config
          key: log-level
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let plan = validate_and_plan(&name, spec).unwrap();
        assert!(matches!(
            plan.containers[0].env[0].1,
            KubeEnvValue::ConfigMapKeyRef { .. }
        ));
        if let KubeEnvValue::ConfigMapKeyRef { ref name, ref key } = plan.containers[0].env[0].1 {
            assert_eq!(name, "app-config");
            assert_eq!(key, "log-level");
        }
    }

    #[test]
    fn test_parse_env_value_from_invalid() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: env-pod
spec:
  containers:
  - name: app
    image: docker.io/busybox:latest
    env:
    - name: BAD_VAR
      valueFrom: {}
"#;
        let (name, spec) = parse_yaml(yaml).unwrap();
        let err = validate_and_plan(&name, spec).unwrap_err();
        assert!(
            err.to_string()
                .contains("valueFrom must specify secretKeyRef or configMapKeyRef"),
            "unexpected error: {err}"
        );
    }
}
