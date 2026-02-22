//! Internal API for container filesystem, state, and runtime management.
//!
//! Each container gets an overlayfs directory tree (`upper/work/merged/shared`)
//! under the configured data directory and a KEY=VALUE state file that tracks
//! its metadata. All mutating operations follow a transaction-style pattern:
//! work is performed step-by-step and, on failure, partially-created artifacts
//! are cleaned up before the error is returned. New implementations and changes
//! should conform to this pattern.

use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::{State, systemd, validate_name};

pub struct CreateOptions {
    pub name: Option<String>,
    pub rootfs: Option<String>,
}

pub fn create(datadir: &Path, opts: &CreateOptions, verbose: bool) -> Result<String> {
    let name = match &opts.name {
        Some(n) => n.clone(),
        None => generate_name(),
    };
    validate_name(&name)?;
    if verbose {
        eprintln!("container name: {name}");
    }
    check_conflicts(datadir, &name)?;
    if verbose {
        eprintln!("no conflicts found");
    }
    let rootfs = resolve_rootfs(datadir, opts.rootfs.as_deref())?;
    if verbose {
        eprintln!("rootfs: {}", rootfs.display());
    }

    match do_create(datadir, &name, &rootfs, verbose) {
        Ok(()) => Ok(name),
        Err(e) => {
            let container_dir = datadir.join("containers").join(&name);
            let state_file = datadir.join("state").join(&name);
            let _ = fs::remove_dir_all(&container_dir);
            let _ = fs::remove_file(&state_file);
            Err(e)
        }
    }
}

fn do_create(datadir: &Path, name: &str, rootfs: &Path, verbose: bool) -> Result<()> {
    let container_dir = datadir.join("containers").join(name);

    for sub in &["upper", "work", "merged", "shared"] {
        let dir = container_dir.join(sub);
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }

    if verbose {
        eprintln!("created container directory: {}", container_dir.display());
    }

    let etc_dir = container_dir.join("upper").join("etc");
    fs::create_dir_all(&etc_dir)
        .with_context(|| format!("failed to create {}", etc_dir.display()))?;

    let hostname_path = etc_dir.join("hostname");
    fs::write(&hostname_path, format!("{name}\n"))
        .with_context(|| format!("failed to write {}", hostname_path.display()))?;

    let hosts_path = etc_dir.join("hosts");
    fs::write(&hosts_path, format!("127.0.0.1 {name}\n"))
        .with_context(|| format!("failed to write {}", hosts_path.display()))?;

    if verbose {
        eprintln!("wrote hostname and hosts files");
    }

    let state_dir = datadir.join("state");
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("failed to create {}", state_dir.display()))?;

    let rootfs_value = if rootfs == Path::new("/") {
        String::new()
    } else {
        rootfs
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    };

    let mut state = State::new();
    state.set("CREATED", unix_timestamp().to_string());
    state.set("NAME", name);
    state.set("ROOTFS", rootfs_value);

    let state_path = datadir.join("state").join(name);
    state.write_to(&state_path)?;

    if verbose {
        eprintln!("wrote state file: {}", state_path.display());
    }

    Ok(())
}

fn generate_name() -> String {
    let mut buf = [0u8; 10];
    let mut f = fs::File::open("/dev/urandom").expect("failed to open /dev/urandom");
    f.read_exact(&mut buf).expect("failed to read /dev/urandom");
    buf.iter().map(|b| (b'a' + (b % 26)) as char).collect()
}

fn check_conflicts(datadir: &Path, name: &str) -> Result<()> {
    let container_dir = datadir.join("containers").join(name);
    if container_dir.exists() {
        bail!("container already exists: {name}");
    }
    let state_file = datadir.join("state").join(name);
    if state_file.exists() {
        bail!("state file already exists for: {name}");
    }
    let machines_dir = Path::new("/var/lib/machines").join(name);
    if machines_dir.exists() {
        bail!("conflicting machine found in /var/lib/machines: {name}");
    }
    Ok(())
}

fn resolve_rootfs(datadir: &Path, rootfs: Option<&str>) -> Result<PathBuf> {
    match rootfs {
        None => Ok(PathBuf::from("/")),
        Some(name) => {
            let path = datadir.join("rootfs").join(name);
            if !path.exists() {
                bail!("rootfs not found: {}", path.display());
            }
            Ok(path)
        }
    }
}

pub fn ensure_exists(datadir: &Path, name: &str) -> Result<()> {
    let state_file = datadir.join("state").join(name);
    if !state_file.exists() {
        bail!("container does not exist: {name}");
    }
    let container_dir = datadir.join("containers").join(name);
    if !container_dir.exists() {
        bail!("container '{name}' state file exists but directory is missing");
    }
    Ok(())
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

pub fn remove(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    ensure_exists(datadir, name)?;

    if systemd::is_active(name)? {
        if verbose {
            eprintln!("stopping container '{name}'");
        }
        stop(name, verbose)?;
    }

    let container_dir = datadir.join("containers").join(name);
    if container_dir.exists() {
        fs::remove_dir_all(&container_dir)
            .with_context(|| format!("failed to remove {}", container_dir.display()))?;
        if verbose {
            eprintln!("removed {}", container_dir.display());
        }
    }

    let state_file = datadir.join("state").join(name);
    if state_file.exists() {
        fs::remove_file(&state_file)
            .with_context(|| format!("failed to remove {}", state_file.display()))?;
        if verbose {
            eprintln!("removed {}", state_file.display());
        }
    }

    Ok(())
}

pub struct ContainerInfo {
    pub name: String,
    pub status: String,
    pub health: String,
    pub shared: PathBuf,
}

pub fn list(datadir: &Path) -> Result<Vec<ContainerInfo>> {
    let state_dir = datadir.join("state");
    if !state_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<String> = Vec::new();
    for entry in fs::read_dir(&state_dir)
        .with_context(|| format!("failed to read {}", state_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(name) = entry.file_name().to_str() {
                entries.push(name.to_string());
            }
        }
    }
    entries.sort();

    let mut result = Vec::new();
    for name in &entries {
        let container_dir = datadir.join("containers").join(name);
        let shared = container_dir.join("shared");

        // Health checks.
        let mut problems = Vec::new();
        if !container_dir.exists() {
            problems.push("missing container dir");
        }
        let state_path = state_dir.join(name);
        let state = State::read_from(&state_path);
        match &state {
            Ok(s) => {
                let rootfs_name = s.get("ROOTFS").unwrap_or("");
                if !rootfs_name.is_empty() && !datadir.join("rootfs").join(rootfs_name).exists() {
                    problems.push("missing rootfs");
                }
            }
            Err(_) => {
                problems.push("unreadable state file");
            }
        }

        let health = if problems.is_empty() {
            "ok".to_string()
        } else {
            problems.join(", ")
        };

        // Status (running/stopped).
        let status = if container_dir.exists() {
            match systemd::is_active(name) {
                Ok(true) => "running",
                _ => "stopped",
            }
        } else {
            "stopped"
        };

        result.push(ContainerInfo {
            name: name.clone(),
            status: status.to_string(),
            health,
            shared,
        });
    }
    Ok(result)
}

pub fn join(
    datadir: &Path,
    name: &str,
    command: &[String],
    verbose: bool,
) -> Result<()> {
    ensure_exists(datadir, name)?;

    if !systemd::is_active(name)? {
        bail!("container '{name}' is not running");
    }

    machinectl_shell(name, command, verbose)
}

pub fn exec(name: &str, command: &[String], verbose: bool) -> Result<()> {
    if !systemd::is_active(name)? {
        bail!("container '{name}' is not running");
    }

    machinectl_shell(name, command, verbose)
}

fn machinectl_shell(name: &str, command: &[String], verbose: bool) -> Result<()> {
    let mut cmd = std::process::Command::new("machinectl");
    cmd.arg("shell").arg(name);
    if !command.is_empty() {
        cmd.args(command);
    }
    if verbose {
        eprintln!("exec: machinectl {}",
            cmd.get_args()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    let err = cmd.exec();
    bail!("failed to exec machinectl: {err}");
}

pub fn stop(name: &str, verbose: bool) -> Result<()> {
    let mut cmd = std::process::Command::new("machinectl");
    cmd.args(["poweroff", name]);
    if verbose {
        eprintln!("exec: machinectl poweroff {name}");
    }
    let status = cmd
        .status()
        .context("failed to exec machinectl poweroff")?;
    if !status.success() {
        bail!("machinectl poweroff failed for '{name}'");
    }
    Ok(())
}

pub fn wait_for_boot(name: &str, verbose: bool) -> Result<()> {
    let timeout = std::time::Duration::from_secs(30);
    let poll_interval = std::time::Duration::from_millis(500);
    let start = std::time::Instant::now();

    if verbose {
        eprintln!("waiting for container '{name}' to boot...");
    }

    loop {
        let output = std::process::Command::new("machinectl")
            .args(["show", name, "--property=State", "--value"])
            .output()
            .context("failed to exec machinectl show")?;

        if output.status.success() {
            let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if verbose {
                eprintln!("container state: {state}");
            }
            if state == "running" {
                return Ok(());
            }
        }

        if start.elapsed() > timeout {
            bail!("timed out waiting for container '{name}' to boot (30s)");
        }

        std::thread::sleep(poll_interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDataDir {
        dir: PathBuf,
    }

    impl TempDataDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-containers-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn path(&self) -> &Path {
            &self.dir
        }
    }

    impl Drop for TempDataDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn test_generate_name() {
        let name1 = generate_name();
        let name2 = generate_name();
        assert_eq!(name1.len(), 10);
        assert_eq!(name2.len(), 10);
        assert!(name1.chars().all(|c| c.is_ascii_lowercase()));
        assert!(name2.chars().all(|c| c.is_ascii_lowercase()));
        assert_ne!(name1, name2);
    }

    #[test]
    fn test_validate_name_ok() {
        assert!(validate_name("mycontainer").is_ok());
        assert!(validate_name("test123").is_ok());
        assert!(validate_name("a").is_ok());
        assert!(validate_name("my-container").is_ok());
    }

    #[test]
    fn test_validate_name_invalid() {
        assert!(validate_name("").is_err());
        assert!(validate_name("MyContainer").is_err());
        assert!(validate_name("has space").is_err());
        assert!(validate_name("1startsdigit").is_err());
        assert!(validate_name("-startshyphen").is_err());
    }

    #[test]
    fn test_state_roundtrip() {
        let mut state = State::new();
        state.set("NAME", "test");
        state.set("CREATED", "1234567890");
        state.set("ROOTFS", "");

        let serialized = state.serialize();
        let parsed = State::parse(&serialized).unwrap();

        assert_eq!(parsed.get("NAME"), Some("test"));
        assert_eq!(parsed.get("CREATED"), Some("1234567890"));
        assert_eq!(parsed.get("ROOTFS"), Some(""));
    }

    #[test]
    fn test_state_parse_value_with_equals() {
        let content = "KEY=val=ue\n";
        let state = State::parse(content).unwrap();
        assert_eq!(state.get("KEY"), Some("val=ue"));
    }

    #[test]
    fn test_create_default() {
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: None,
            rootfs: None,
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name.len(), 10);
        assert!(name.chars().all(|c| c.is_ascii_lowercase()));

        // Verify directories.
        let container_dir = tmp.path().join("containers").join(&name);
        assert!(container_dir.join("upper").is_dir());
        assert!(container_dir.join("work").is_dir());
        assert!(container_dir.join("merged").is_dir());
        assert!(container_dir.join("shared").is_dir());

        // Verify hostname.
        let hostname = fs::read_to_string(container_dir.join("upper/etc/hostname")).unwrap();
        assert_eq!(hostname, format!("{name}\n"));

        // Verify hosts.
        let hosts = fs::read_to_string(container_dir.join("upper/etc/hosts")).unwrap();
        assert_eq!(hosts, format!("127.0.0.1 {name}\n"));

        // Verify state file.
        let state = State::read_from(&tmp.path().join("state").join(&name)).unwrap();
        assert_eq!(state.get("NAME"), Some(name.as_str()));
        assert_eq!(state.get("ROOTFS"), Some(""));
        assert!(state.get("CREATED").is_some());
    }

    #[test]
    fn test_create_with_name() {
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: Some("hello".to_string()),
            rootfs: None,
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "hello");

        let hostname = fs::read_to_string(
            tmp.path()
                .join("containers/hello/upper/etc/hostname"),
        )
        .unwrap();
        assert_eq!(hostname, "hello\n");

        let hosts = fs::read_to_string(
            tmp.path()
                .join("containers/hello/upper/etc/hosts"),
        )
        .unwrap();
        assert_eq!(hosts, "127.0.0.1 hello\n");

        let state = State::read_from(&tmp.path().join("state/hello")).unwrap();
        assert_eq!(state.get("NAME"), Some("hello"));
    }

    #[test]
    fn test_create_duplicate_name() {
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: Some("dup".to_string()),
            rootfs: None,
        };
        create(tmp.path(), &opts, false).unwrap();
        let err = create(tmp.path(), &opts, false).unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_create_with_rootfs_missing() {
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: Some("test".to_string()),
            rootfs: Some("nonexistent".to_string()),
        };
        let err = create(tmp.path(), &opts, false).unwrap_err();
        assert!(
            err.to_string().contains("rootfs not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_create_with_rootfs_exists() {
        let tmp = TempDataDir::new();
        let rootfs_dir = tmp.path().join("rootfs/myroot");
        fs::create_dir_all(&rootfs_dir).unwrap();

        let opts = CreateOptions {
            name: Some("test".to_string()),
            rootfs: Some("myroot".to_string()),
        };
        let name = create(tmp.path(), &opts, false).unwrap();
        assert_eq!(name, "test");

        let state = State::read_from(&tmp.path().join("state/test")).unwrap();
        assert_eq!(state.get("ROOTFS"), Some("myroot"));
    }

    #[test]
    fn test_create_cleanup_on_failure() {
        let tmp = TempDataDir::new();
        // Block state dir by placing a file where the directory should be created.
        let state_path = tmp.path().join("state");
        fs::write(&state_path, "blocker").unwrap();

        let opts = CreateOptions {
            name: Some("fail".to_string()),
            rootfs: None,
        };
        let err = create(tmp.path(), &opts, false);
        assert!(err.is_err());

        // Container dir should have been cleaned up.
        assert!(!tmp.path().join("containers/fail").exists());
    }

    #[test]
    fn test_ensure_exists_ok() {
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: Some("mybox".to_string()),
            rootfs: None,
        };
        create(tmp.path(), &opts, false).unwrap();
        assert!(ensure_exists(tmp.path(), "mybox").is_ok());
    }

    #[test]
    fn test_ensure_exists_missing() {
        let tmp = TempDataDir::new();
        let err = ensure_exists(tmp.path(), "nonexistent").unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_ensure_exists_orphan_state() {
        let tmp = TempDataDir::new();
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(state_dir.join("orphan"), "NAME=orphan\n").unwrap();

        let err = ensure_exists(tmp.path(), "orphan").unwrap_err();
        assert!(
            err.to_string().contains("directory is missing"),
            "unexpected error: {err}"
        );
    }
}
