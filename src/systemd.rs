//! Internal API for managing interactions with systemd and D-Bus.
//!
//! Provides helpers for installing the `sdme@.service` template unit,
//! writing per-container environment files, and starting containers
//! via the systemd D-Bus interface.

use std::fs;
use std::path::Path;

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::State;

mod dbus {
    use anyhow::{Context, Result};
    use zbus::blocking::proxy::Proxy;
    use zbus::blocking::Connection;

    fn connect(privileged: bool) -> Result<Connection> {
        if privileged {
            Connection::system().context("failed to connect to system dbus")
        } else {
            Connection::session().context("failed to connect to session dbus")
        }
    }

    fn systemd_manager(conn: &Connection) -> Result<Proxy<'_>> {
        Proxy::new(
            conn,
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .context("failed to create systemd manager proxy")
    }

    pub fn daemon_reload(privileged: bool) -> Result<()> {
        let conn = connect(privileged)?;
        let proxy = systemd_manager(&conn)?;
        proxy
            .call_method("Reload", &())
            .context("systemctl daemon-reload failed")?;
        Ok(())
    }

    pub fn start_unit(unit: &str, privileged: bool) -> Result<()> {
        let conn = connect(privileged)?;
        let proxy = systemd_manager(&conn)?;
        proxy
            .call_method("StartUnit", &(unit, "replace"))
            .with_context(|| format!("systemctl start {unit} failed"))?;
        Ok(())
    }

    pub fn stop_unit(unit: &str, privileged: bool) -> Result<()> {
        let conn = connect(privileged)?;
        let proxy = systemd_manager(&conn)?;
        proxy
            .call_method("StopUnit", &(unit, "replace"))
            .with_context(|| format!("systemctl stop {unit} failed"))?;
        Ok(())
    }

    pub fn get_unit_main_pid(unit: &str, privileged: bool) -> Result<u32> {
        let conn = connect(privileged)?;
        let manager = systemd_manager(&conn)?;
        let unit_path: zbus::zvariant::OwnedObjectPath = manager
            .call_method("GetUnit", &(unit,))
            .with_context(|| format!("failed to get unit {unit}"))?
            .body()
            .deserialize()
            .context("failed to deserialize unit path")?;
        let svc_proxy = Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            unit_path,
            "org.freedesktop.systemd1.Service",
        )
        .context("failed to create service proxy")?;
        svc_proxy
            .get_property::<u32>("MainPID")
            .context("failed to read MainPID")
    }

    pub fn is_unit_active(unit: &str, privileged: bool) -> Result<bool> {
        let conn = connect(privileged)?;
        let manager = systemd_manager(&conn)?;
        let unit_path: zbus::zvariant::OwnedObjectPath = manager
            .call_method("GetUnit", &(unit,))
            .with_context(|| format!("failed to get unit {unit}"))?
            .body()
            .deserialize()
            .context("failed to deserialize unit path")?;
        let unit_proxy = Proxy::new(
            &conn,
            "org.freedesktop.systemd1",
            unit_path,
            "org.freedesktop.systemd1.Unit",
        )
        .context("failed to create unit proxy")?;
        let state: String = unit_proxy
            .get_property("ActiveState")
            .context("failed to read ActiveState")?;
        Ok(state == "active")
    }

    pub fn get_systemd_version(privileged: bool) -> Result<String> {
        let conn = connect(privileged)?;
        let proxy = systemd_manager(&conn)?;
        proxy
            .get_property::<String>("Version")
            .context("failed to read systemd version")
    }
}

pub fn systemd_version(privileged: bool) -> Result<String> {
    dbus::get_systemd_version(privileged)
}

pub fn stop(name: &str, privileged: bool) -> Result<()> {
    dbus::stop_unit(&service_name(name), privileged)
}

pub fn is_active(name: &str, privileged: bool) -> Result<bool> {
    match dbus::is_unit_active(&service_name(name), privileged) {
        Ok(active) => Ok(active),
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("NoSuchUnit") || msg.contains("not loaded") {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

pub fn get_main_pid(name: &str, privileged: bool) -> Result<u32> {
    dbus::get_unit_main_pid(&service_name(name), privileged)
}

pub fn service_name(name: &str) -> String {
    format!("sdme@{name}.service")
}

pub fn resolve_paths(privileged: bool) -> Result<UnitPaths> {
    use crate::system_check::find_program;
    let nspawn = find_program("systemd-nspawn")
        .context("systemd-nspawn not found; install systemd-container")?;
    if privileged {
        let mount = find_program("mount")
            .context("mount not found")?;
        let umount = find_program("umount")
            .context("umount not found")?;
        Ok(UnitPaths::Privileged { nspawn, mount, umount })
    } else {
        let fuse_overlayfs = find_program("fuse-overlayfs")
            .context("fuse-overlayfs not found; install fuse-overlayfs")?;
        let fusermount = find_program("fusermount")
            .context("fusermount not found; install fuse3")?;
        Ok(UnitPaths::Rootless { nspawn, fuse_overlayfs, fusermount })
    }
}

pub enum UnitPaths {
    Privileged {
        nspawn: PathBuf,
        mount: PathBuf,
        umount: PathBuf,
    },
    Rootless {
        nspawn: PathBuf,
        fuse_overlayfs: PathBuf,
        fusermount: PathBuf,
    },
}

pub fn unit_template(datadir: &str, paths: &UnitPaths) -> String {
    let UnitPaths::Privileged { nspawn, mount, umount } = paths else {
        panic!("unit_template called with rootless paths");
    };
    let mount = mount.display();
    let umount = umount.display();
    let nspawn = nspawn.display();
    format!(
        r#"[Unit]
Description=sdme container %i
After=network.target local-fs.target

[Service]
Type=simple
EnvironmentFile={datadir}/containers/%i/env
ExecStartPre={mount} -t overlay overlay \
    -o lowerdir=${{LOWERDIR}},upperdir={datadir}/containers/%i/upper,workdir={datadir}/containers/%i/work \
    {datadir}/containers/%i/merged
ExecStart={nspawn} \
    --directory={datadir}/containers/%i/merged \
    --machine=%i \
    --bind={datadir}/containers/%i/shared:/shared \
    --resolv-conf=auto \
    --boot
ExecStopPost=-{umount} {datadir}/containers/%i/merged
KillMode=mixed
Delegate=yes
"#
    )
}

pub fn rootless_unit_template(datadir: &str, paths: &UnitPaths) -> String {
    let UnitPaths::Rootless { nspawn, fuse_overlayfs, fusermount } = paths else {
        panic!("rootless_unit_template called with privileged paths");
    };
    let fuse_overlayfs = fuse_overlayfs.display();
    let fusermount = fusermount.display();
    let nspawn = nspawn.display();
    format!(
        r#"[Unit]
Description=sdme container %i

[Service]
Type=simple
EnvironmentFile={datadir}/containers/%i/env
ExecStartPre={fuse_overlayfs} \
    -o lowerdir=${{LOWERDIR}},upperdir={datadir}/containers/%i/upper,workdir={datadir}/containers/%i/work \
    {datadir}/containers/%i/merged
ExecStart={nspawn} \
    --directory={datadir}/containers/%i/merged \
    --machine=%i \
    --private-users=managed \
    --private-network \
    --bind={datadir}/containers/%i/shared:/shared \
    --resolv-conf=auto \
    --register=no \
    --boot
ExecStopPost=-{fusermount} -u {datadir}/containers/%i/merged
KillMode=mixed
Delegate=yes
"#
    )
}

fn user_unit_dir() -> Result<PathBuf> {
    let base = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else {
        let home = std::env::var("HOME").context("HOME not set")?;
        PathBuf::from(home).join(".config")
    };
    Ok(base.join("systemd").join("user"))
}

fn check_linger() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let username = std::env::var("USER").unwrap_or_else(|_| uid.to_string());
    let output = std::process::Command::new("loginctl")
        .args(["show-user", &username, "--property=Linger", "--value"])
        .output()
        .context("failed to run loginctl show-user")?;
    if output.status.success() {
        let value = String::from_utf8_lossy(&output.stdout);
        if value.trim() == "yes" {
            return Ok(());
        }
    }
    bail!(
        "linger not enabled for user '{}'\nrun: loginctl enable-linger {}",
        username,
        username
    );
}

fn write_unit_if_changed(unit_path: &Path, content: &str, verbose: bool) -> Result<bool> {
    if unit_path.exists() {
        let existing = fs::read_to_string(unit_path)
            .with_context(|| format!("failed to read {}", unit_path.display()))?;
        if existing == content {
            if verbose {
                eprintln!("template unit up to date: {}", unit_path.display());
            }
            return Ok(false);
        }
        if verbose {
            eprintln!("updating template unit: {}", unit_path.display());
        }
    } else if verbose {
        eprintln!("installing template unit: {}", unit_path.display());
    }
    fs::write(unit_path, content).with_context(|| {
        format!("failed to write template unit {}", unit_path.display())
    })?;
    Ok(true)
}

fn ensure_template_unit(datadir: &Path, verbose: bool, privileged: bool) -> Result<()> {
    let datadir_str = datadir
        .to_str()
        .context("datadir path is not valid UTF-8")?;

    let paths = resolve_paths(privileged)?;
    if verbose {
        match &paths {
            UnitPaths::Privileged { nspawn, mount, umount } => {
                eprintln!("found mount: {}", mount.display());
                eprintln!("found umount: {}", umount.display());
                eprintln!("found systemd-nspawn: {}", nspawn.display());
            }
            UnitPaths::Rootless { nspawn, fuse_overlayfs, fusermount } => {
                eprintln!("found fuse-overlayfs: {}", fuse_overlayfs.display());
                eprintln!("found fusermount: {}", fusermount.display());
                eprintln!("found systemd-nspawn: {}", nspawn.display());
            }
        }
    }

    if privileged {
        let unit_path = Path::new("/etc/systemd/system/sdme@.service");
        let content = unit_template(datadir_str, &paths);
        if write_unit_if_changed(unit_path, &content, verbose)? {
            dbus::daemon_reload(privileged)?;
        }
    } else {
        let unit_dir = user_unit_dir()?;
        fs::create_dir_all(&unit_dir)
            .with_context(|| format!("failed to create {}", unit_dir.display()))?;
        let unit_path = unit_dir.join("sdme@.service");
        let content = rootless_unit_template(datadir_str, &paths);
        if write_unit_if_changed(&unit_path, &content, verbose)? {
            dbus::daemon_reload(privileged)?;
        }
    }
    Ok(())
}

pub fn write_env_file(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    let state_path = datadir.join("state").join(name);
    let state = State::read_from(&state_path)?;
    let rootfs = state.get("ROOTFS").unwrap_or("");
    let lowerdir = if rootfs.is_empty() {
        "/".to_string()
    } else {
        let path = datadir.join("rootfs").join(rootfs);
        path.to_str()
            .context("rootfs path is not valid UTF-8")?
            .to_string()
    };
    if verbose {
        eprintln!("lowerdir: {lowerdir}");
    }
    let env_path = datadir.join("containers").join(name).join("env");
    fs::write(&env_path, format!("LOWERDIR={lowerdir}\n"))
        .with_context(|| format!("failed to write {}", env_path.display()))?;
    if verbose {
        eprintln!("wrote env file: {}", env_path.display());
    }
    Ok(())
}

pub fn start(datadir: &Path, name: &str, verbose: bool, privileged: bool) -> Result<()> {
    if !privileged {
        check_linger()?;
    }

    ensure_template_unit(datadir, verbose, privileged)?;

    if privileged {
        let env_path = datadir.join("containers").join(name).join("env");
        write_env_file(datadir, name, verbose)?;

        if verbose {
            eprintln!("starting unit: {}", service_name(name));
        }
        if let Err(e) = dbus::start_unit(&service_name(name), privileged) {
            let _ = fs::remove_file(&env_path);
            return Err(e);
        }
    } else {
        let env_path = datadir.join("containers").join(name).join("env");
        write_env_file(datadir, name, verbose)?;

        if verbose {
            eprintln!("starting unit: {}", service_name(name));
        }
        if let Err(e) = dbus::start_unit(&service_name(name), privileged) {
            let _ = fs::remove_file(&env_path);
            return Err(e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::{create, CreateOptions};
    use std::path::PathBuf;

    struct TempDataDir {
        dir: PathBuf,
    }

    impl TempDataDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-systemd-{}-{:?}",
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
    fn test_service_name() {
        assert_eq!(service_name("mybox"), "sdme@mybox.service");
    }

    fn test_privileged_paths() -> UnitPaths {
        UnitPaths::Privileged {
            nspawn: PathBuf::from("/usr/bin/systemd-nspawn"),
            mount: PathBuf::from("/usr/bin/mount"),
            umount: PathBuf::from("/usr/bin/umount"),
        }
    }

    fn test_rootless_paths() -> UnitPaths {
        UnitPaths::Rootless {
            nspawn: PathBuf::from("/usr/bin/systemd-nspawn"),
            fuse_overlayfs: PathBuf::from("/usr/bin/fuse-overlayfs"),
            fusermount: PathBuf::from("/usr/bin/fusermount"),
        }
    }

    #[test]
    fn test_unit_template() {
        let paths = test_privileged_paths();
        let template = unit_template("/var/lib/sdme", &paths);
        assert!(template.contains("Description=sdme container %i"));
        assert!(template.contains("EnvironmentFile=/var/lib/sdme/containers/%i/env"));
        assert!(template.contains("lowerdir=${LOWERDIR}"));
        assert!(template.contains("upperdir=/var/lib/sdme/containers/%i/upper"));
        assert!(template.contains("workdir=/var/lib/sdme/containers/%i/work"));
        assert!(template.contains("/var/lib/sdme/containers/%i/merged"));
        assert!(template.contains("--machine=%i"));
        assert!(template.contains("--bind=/var/lib/sdme/containers/%i/shared:/shared"));
        assert!(template.contains("--resolv-conf=auto"));
        assert!(template.contains("--boot"));
        assert!(template.contains("Delegate=yes"));
        assert!(template.contains("/usr/bin/systemd-nspawn"));
        assert!(template.contains("/usr/bin/mount"));
        assert!(template.contains("/usr/bin/umount"));
    }

    #[test]
    fn test_unit_template_custom_datadir() {
        let paths = test_privileged_paths();
        let template = unit_template("/tmp/custom", &paths);
        assert!(template.contains("EnvironmentFile=/tmp/custom/containers/%i/env"));
        assert!(template.contains("upperdir=/tmp/custom/containers/%i/upper"));
        assert!(template.contains("workdir=/tmp/custom/containers/%i/work"));
        assert!(template.contains("/tmp/custom/containers/%i/merged"));
        assert!(template.contains("--bind=/tmp/custom/containers/%i/shared:/shared"));
    }

    #[test]
    fn test_rootless_unit_template() {
        let paths = test_rootless_paths();
        let template = rootless_unit_template("/home/user/.local/state/sdme", &paths);
        assert!(template.contains("Description=sdme container %i"));
        assert!(template.contains("EnvironmentFile=/home/user/.local/state/sdme/containers/%i/env"));
        assert!(template.contains("/usr/bin/fuse-overlayfs"));
        assert!(template.contains("lowerdir=${LOWERDIR}"));
        assert!(template.contains("upperdir=/home/user/.local/state/sdme/containers/%i/upper"));
        assert!(template.contains("workdir=/home/user/.local/state/sdme/containers/%i/work"));
        assert!(template.contains("--directory=/home/user/.local/state/sdme/containers/%i/merged"));
        assert!(template.contains("--private-users=managed"));
        assert!(template.contains("--private-network"));
        assert!(template.contains("--register=no"));
        assert!(template.contains("--bind=/home/user/.local/state/sdme/containers/%i/shared:/shared"));
        assert!(template.contains("--boot"));
        assert!(template.contains("Delegate=yes"));
        assert!(template.contains("/usr/bin/fusermount -u"));
        assert!(template.contains("/usr/bin/systemd-nspawn"));
    }

    #[test]
    fn test_write_env_file_host_rootfs() {
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: Some("hostbox".to_string()),
            rootfs: None,
            privileged: true,
        };
        create(tmp.path(), &opts, false).unwrap();

        write_env_file(tmp.path(), "hostbox", false).unwrap();

        let env_path = tmp.path().join("containers/hostbox/env");
        let content = fs::read_to_string(&env_path).unwrap();
        assert_eq!(content, "LOWERDIR=/\n");
    }

    #[test]
    fn test_write_env_file_explicit_rootfs() {
        let tmp = TempDataDir::new();
        let rootfs_dir = tmp.path().join("rootfs/ubuntu");
        fs::create_dir_all(&rootfs_dir).unwrap();

        let opts = CreateOptions {
            name: Some("ubox".to_string()),
            rootfs: Some("ubuntu".to_string()),
            privileged: true,
        };
        create(tmp.path(), &opts, false).unwrap();

        write_env_file(tmp.path(), "ubox", false).unwrap();

        let env_path = tmp.path().join("containers/ubox/env");
        let content = fs::read_to_string(&env_path).unwrap();
        let expected = format!("LOWERDIR={}/rootfs/ubuntu\n", tmp.path().display());
        assert_eq!(content, expected);
    }
}
