//! Internal API for managing interactions with systemd and D-Bus.
//!
//! Provides helpers for installing the `sdme@.service` template unit,
//! writing per-container environment files, and starting containers
//! via the systemd D-Bus interface.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::containers::State;

mod dbus {
    use anyhow::{Context, Result};
    use zbus::blocking::proxy::Proxy;
    use zbus::blocking::Connection;

    fn system_bus() -> Result<Connection> {
        Connection::system().context("failed to connect to system dbus")
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

    pub fn daemon_reload() -> Result<()> {
        let conn = system_bus()?;
        let proxy = systemd_manager(&conn)?;
        proxy
            .call_method("Reload", &())
            .context("systemctl daemon-reload failed")?;
        Ok(())
    }

    pub fn start_unit(unit: &str) -> Result<()> {
        let conn = system_bus()?;
        let proxy = systemd_manager(&conn)?;
        proxy
            .call_method("StartUnit", &(unit, "replace"))
            .with_context(|| format!("systemctl start {unit} failed"))?;
        Ok(())
    }
}

pub fn service_name(name: &str) -> String {
    format!("sdme@{name}.service")
}

pub fn unit_template(datadir: &str) -> String {
    format!(
        r#"[Unit]
Description=sdme container %i
After=network.target local-fs.target

[Service]
Type=simple
EnvironmentFile={datadir}/containers/%i/env
ExecStartPre=/bin/mount -t overlay overlay \
    -o lowerdir=${{LOWERDIR}},upperdir={datadir}/containers/%i/upper,workdir={datadir}/containers/%i/work \
    {datadir}/containers/%i/merged
ExecStart=/usr/bin/systemd-nspawn \
    --directory={datadir}/containers/%i/merged \
    --machine=%i \
    --bind={datadir}/containers/%i/shared:/shared \
    --resolv-conf=auto \
    --boot
ExecStopPost=-/bin/umount {datadir}/containers/%i/merged
KillMode=mixed
Delegate=yes
"#
    )
}

fn ensure_template_unit(datadir: &Path, verbose: bool) -> Result<()> {
    let unit_path = Path::new("/etc/systemd/system/sdme@.service");
    if unit_path.exists() {
        if verbose {
            eprintln!("template unit already installed");
        }
        return Ok(());
    }
    let datadir_str = datadir
        .to_str()
        .context("datadir path is not valid UTF-8")?;
    let content = unit_template(datadir_str);
    fs::write(unit_path, content).with_context(|| {
        format!("failed to write template unit {}", unit_path.display())
    })?;
    dbus::daemon_reload()?;
    if verbose {
        eprintln!("installed template unit: {}", unit_path.display());
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

pub fn start(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    ensure_template_unit(datadir, verbose)?;

    let env_path = datadir.join("containers").join(name).join("env");
    write_env_file(datadir, name, verbose)?;

    if verbose {
        eprintln!("starting unit: {}", service_name(name));
    }
    if let Err(e) = dbus::start_unit(&service_name(name)) {
        let _ = fs::remove_file(&env_path);
        return Err(e);
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

    #[test]
    fn test_unit_template() {
        let template = unit_template("/var/lib/sdme");
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
    }

    #[test]
    fn test_unit_template_custom_datadir() {
        let template = unit_template("/tmp/custom");
        assert!(template.contains("EnvironmentFile=/tmp/custom/containers/%i/env"));
        assert!(template.contains("upperdir=/tmp/custom/containers/%i/upper"));
        assert!(template.contains("workdir=/tmp/custom/containers/%i/work"));
        assert!(template.contains("/tmp/custom/containers/%i/merged"));
        assert!(template.contains("--bind=/tmp/custom/containers/%i/shared:/shared"));
    }

    #[test]
    fn test_write_env_file_host_rootfs() {
        let tmp = TempDataDir::new();
        let opts = CreateOptions {
            name: Some("hostbox".to_string()),
            rootfs: None,
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
        };
        create(tmp.path(), &opts, false).unwrap();

        write_env_file(tmp.path(), "ubox", false).unwrap();

        let env_path = tmp.path().join("containers/ubox/env");
        let content = fs::read_to_string(&env_path).unwrap();
        let expected = format!("LOWERDIR={}/rootfs/ubuntu\n", tmp.path().display());
        assert_eq!(content, expected);
    }
}
