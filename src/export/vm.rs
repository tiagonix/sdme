//! VM rootfs preparation: patch rootfs for standalone virtual machine boot.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::format_human_size;
use super::RawFs;
use super::VmOptions;
use crate::config::DistroCommands;
use crate::import::InstallPackages;
use crate::rootfs::DistroFamily;

/// Built-in export prehook commands for each distro family.
///
/// Container/rootfs exports (non-VM). Restores file capabilities
/// stripped during import so exported rootfs are intact.
pub fn builtin_export_prehook(family: &DistroFamily) -> Vec<String> {
    match *family {
        DistroFamily::Suse => vec![
            "setcap cap_setuid=ep /usr/bin/newuidmap 2>/dev/null || true".into(),
            "setcap cap_setgid=ep /usr/bin/newgidmap 2>/dev/null || true".into(),
        ],
        _ => vec![],
    }
}

/// Built-in VM export prehook commands for each distro family.
///
/// Installs udev and any other VM boot dependencies.
pub fn builtin_export_vm_prehook(family: &DistroFamily) -> Vec<String> {
    use crate::import::APT_NO_SANDBOX;
    match *family {
        DistroFamily::Debian => vec![
            format!("apt-get update -qq {APT_NO_SANDBOX}"),
            format!("apt-get install -y {APT_NO_SANDBOX} udev"),
            "apt-get clean".into(),
            "rm -rf /var/lib/apt/lists/*".into(),
        ],
        DistroFamily::Fedora => vec![
            "dnf install -y systemd-udevd".into(),
            "dnf clean all".into(),
        ],
        DistroFamily::Arch => vec![
            "pacman -Sy --noconfirm systemd".into(),
            "pacman -Scc --noconfirm".into(),
        ],
        DistroFamily::Suse => vec![
            "zypper --non-interactive install udev".into(),
            "zypper clean --all".into(),
            "setcap cap_setuid=ep /usr/bin/newuidmap 2>/dev/null || true".into(),
            "setcap cap_setgid=ep /usr/bin/newgidmap 2>/dev/null || true".into(),
        ],
        _ => vec![],
    }
}

/// Resolve export prehook commands: config override, then built-in default.
///
/// Not wired yet (container/rootfs export hooks are empty today).
#[allow(dead_code)]
fn resolve_export_prehook(
    family: &DistroFamily,
    distros: &HashMap<String, DistroCommands>,
) -> Vec<String> {
    if let Some(cfg) = distros.get(family.config_key()) {
        if let Some(cmds) = &cfg.export_prehook {
            return cmds.clone();
        }
    }
    builtin_export_prehook(family)
}

/// Resolve VM export prehook commands: config override, then built-in default.
fn resolve_export_vm_prehook(
    family: &DistroFamily,
    distros: &HashMap<String, DistroCommands>,
) -> Vec<String> {
    if let Some(cfg) = distros.get(family.config_key()) {
        if let Some(cmds) = &cfg.export_vm_prehook {
            return cmds.clone();
        }
    }
    builtin_export_vm_prehook(family)
}

/// Run the distro-specific VM export prehook, respecting the
/// `--install-packages` policy (Auto/Yes/No).
///
/// The prehook handles all distro-specific VM preparation (e.g. installing
/// udev on Debian/Fedora).
fn run_vm_prehook(mount: &Path, opts: &VmOptions, verbose: bool) -> Result<()> {
    let family = crate::rootfs::detect_distro_family(mount);
    let commands = resolve_export_vm_prehook(&family, &opts.distros);
    if commands.is_empty() {
        if verbose {
            eprintln!("no VM prehook commands for distro family {:?}", family);
        }
        return Ok(());
    }

    match opts.install_packages {
        InstallPackages::No => {
            if verbose {
                eprintln!("skipping VM prehook (--install-packages=no)");
            }
            return Ok(());
        }
        InstallPackages::Auto => {
            if opts.interactive {
                let proceed =
                    crate::confirm_default_yes("run VM export prehook for this rootfs? [Y/n] ")?;
                if !proceed {
                    eprintln!("skipping VM prehook");
                    return Ok(());
                }
            } else {
                bail!(
                    "VM prehook available for {:?} but cannot prompt in non-interactive mode; \
                     use --install-packages=yes to run or --install-packages=no to skip",
                    family
                );
            }
        }
        InstallPackages::Yes => {}
    }

    eprintln!("running VM prehook for {:?}...", family);
    let mut chroot_guard = crate::import::ChrootGuard::setup(mount, verbose)?;
    let result = crate::import::run_chroot_commands(mount, &commands, verbose);
    chroot_guard.cleanup();
    result?;
    eprintln!("VM prehook completed");

    Ok(())
}

/// Patch an nspawn-imported rootfs so it can boot as a standalone VM.
///
/// Container rootfs images are imported for systemd-nspawn which provides its
/// own device tree, network, and init discovery. A bare VM kernel needs all of
/// that configured on disk. This function makes the following modifications:
///
/// # Files created or modified
///
/// | What | Path(s) | Why |
/// |------|---------|-----|
/// | VM prehook | (via chroot) | Distro-specific VM prep (udev, etc.); runs if `--install-packages` allows |
/// | init symlink | `/usr/sbin/init` -> `../../lib/systemd/systemd` | Kernel needs `/sbin/init`; nspawn finds systemd directly |
/// | serial-getty template | `/etc/systemd/system/serial-getty@.service` | Copy of distro template with `BindsTo=dev-%i.device` removed (no udev) |
/// | serial-getty enable | `/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service` | Explicit enable for ttyS0 |
/// | multi-user drop-in | `/etc/systemd/system/multi-user.target.d/wants-getty.conf` | `Wants=serial-getty@ttyS0.service`; container images omit getty.target |
/// | fstab | `/etc/fstab` | `/dev/vda1 / {ext4,btrfs} defaults 0 1` |
/// | resolved unmask | `/etc/systemd/system/systemd-resolved.service` | Remove mask symlink (nspawn import masks it) |
/// | resolv.conf | `/etc/resolv.conf` | Only when `--dns` is passed: explicit nameservers or host copy |
/// | networkd units | `/etc/systemd/network/20-sdme-en.network` | DHCP on `en*` interfaces; enables `systemd-networkd.service` |
/// | hostname | `/etc/hostname` | VM hostname (defaults to rootfs/container name) |
/// | root password | `/etc/shadow` | Direct hash write (no chpasswd dependency) |
/// | SSH key | `/root/.ssh/authorized_keys` | Optional authorized_keys for root |
///
/// # Known limitations
///
/// - **GPT partition table**: VM exports create a GPT partition table via
///   `sfdisk` with a single Linux partition at 1 MiB offset. The filesystem
///   is on the partition (not the whole device), avoiding sector 0 conflicts
///   with hypervisors like cloud-hypervisor. Non-VM exports remain bare.
///
/// - **Serial console on AlmaLinux / RHEL 10 (systemd 257)**: the serial
///   getty starts and login works, but the interactive console is unreliable
///   (characters lost, partial commands executed). This appears to be a
///   cloud-hypervisor serial (`--serial tty`) interaction issue with the
///   distro's bash/readline configuration. `init=/bin/sh` works fine on the
///   same image. Workaround: use `--serial pty` and connect with
///   `screen /dev/pts/N`, or use SSH instead of the serial console.
///
/// - **No udev**: container-imported rootfs images typically lack
///   `systemd-udevd`. Use `--install-packages=yes` to install udev into the
///   rootfs during export. The serial-getty template is patched to remove the
///   `BindsTo=dev-%i.device` dependency regardless, so the serial console
///   works even without udev.
///
/// - **NixOS**: Not all export formats are useful with NixOS rootfs. Directory
///   and tarball exports work (they produce a faithful copy), but VM export
///   (`--vm`) is not supported because NixOS manages its own init, fstab,
///   networkd, and udev configuration declaratively via the Nix store. The
///   file-level patches applied by `prepare_vm_rootfs` (init symlink, fstab,
///   serial-getty, networkd units) conflict with NixOS activation. Use
///   NixOS-native tooling (`nixos-generators`, `nixos-rebuild build-vm`) to
///   build NixOS VM images.
///
/// # TODO: package these modifications
///
/// All the above are direct file writes into the rootfs. Ideally each concern
/// should be an installable package (e.g. `sdme-vm-serial`, `sdme-vm-network`)
/// built for the distro's package manager so users can:
///
/// - `dnf remove sdme-vm-serial` to revert the serial console changes
/// - inspect what was modified via `rpm -ql` / `dpkg -L`
/// - layer their own overrides on top cleanly
///
/// Similarly, the OCI app setup (`/oci/apps/`, sdme-oci-*.service units, the
/// isolate binary, volume mounts) should be its own package so it can be
/// cleanly removed or inspected inside a running container.
pub(super) fn prep_vm_rootfs(
    mount: &Path,
    fs_type: RawFs,
    opts: &VmOptions,
    verbose: bool,
) -> Result<()> {
    // Run the distro prehook first. ChrootGuard copies host resolv.conf
    // for DNS, and cleanup restores the original. The later
    // write_resolv_conf() writes the final VM nameservers.
    run_vm_prehook(mount, opts, verbose)?;

    ensure_init_symlink(mount)?;

    enable_serial_console(mount)?;
    if verbose {
        eprintln!("enabled serial-getty@ttyS0.service");
    }

    write_vm_fstab(mount, fs_type, opts.swap_size)?;
    if verbose {
        eprintln!("wrote /etc/fstab");
    }
    if opts.swap_size > 0 && verbose {
        eprintln!(
            "swap partition: /dev/vda2 ({})",
            format_human_size(opts.swap_size)
        );
    }

    unmask_resolved(mount)?;
    if verbose {
        eprintln!("unmasked systemd-resolved");
    }

    match &opts.nameservers {
        Some(ns) if !ns.is_empty() => {
            write_resolv_conf(mount, ns)?;
            if verbose {
                eprintln!("wrote /etc/resolv.conf");
            }
        }
        Some(_) => {
            copy_host_resolv_conf(mount)?;
            if verbose {
                eprintln!("copied host /etc/resolv.conf");
            }
        }
        None => {
            if verbose {
                eprintln!("skipping /etc/resolv.conf (no --dns specified)");
            }
        }
    }

    if opts.net_ifaces > 0 {
        configure_networkd(mount, opts.net_ifaces)?;
        if verbose {
            eprintln!("configured systemd-networkd with DHCP");
        }
    }

    write_hostname(mount, &opts.hostname)?;
    if verbose {
        eprintln!("wrote /etc/hostname: {}", opts.hostname);
    }

    if let Some(password) = &opts.root_password {
        set_root_password(mount, password)?;
        if verbose {
            if password.is_empty() {
                eprintln!("set passwordless root login");
            } else {
                eprintln!("set root password");
            }
        }
    }

    if let Some(key) = &opts.ssh_key {
        install_ssh_key(mount, key)?;
        if verbose {
            eprintln!("installed SSH authorized key for root");
        }
    }

    Ok(())
}

/// Ensure /sbin/init exists so the kernel can find systemd as PID 1.
///
/// On merged-usr systems `/sbin` is a symlink to `usr/sbin`, so the actual
/// file is created at `usr/sbin/init` as a relative symlink to the systemd
/// binary.
pub(super) fn ensure_init_symlink(mount: &Path) -> Result<()> {
    let sbin_init = mount.join("sbin/init");
    if sbin_init.exists() {
        return Ok(());
    }

    // Find the systemd binary.
    let (systemd_path, rel_target) = if mount.join("lib/systemd/systemd").exists() {
        ("lib/systemd/systemd", "../../lib/systemd/systemd")
    } else if mount.join("usr/lib/systemd/systemd").exists() {
        ("usr/lib/systemd/systemd", "../lib/systemd/systemd")
    } else {
        bail!(
            "systemd binary not found in rootfs (checked lib/systemd/systemd \
             and usr/lib/systemd/systemd): image cannot boot as a VM"
        );
    };

    // Determine where to create the symlink. On merged-usr, /sbin -> usr/sbin,
    // so create usr/sbin/init. Otherwise create sbin/init directly.
    let sbin_meta = mount.join("sbin").symlink_metadata();
    let init_path = if sbin_meta
        .as_ref()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        // merged-usr: /sbin -> usr/sbin
        let usr_sbin = mount.join("usr/sbin");
        fs::create_dir_all(&usr_sbin)
            .with_context(|| format!("failed to create {}", usr_sbin.display()))?;
        mount.join("usr/sbin/init")
    } else {
        let sbin = mount.join("sbin");
        fs::create_dir_all(&sbin)
            .with_context(|| format!("failed to create {}", sbin.display()))?;
        mount.join("sbin/init")
    };

    std::os::unix::fs::symlink(rel_target, &init_path).with_context(|| {
        format!(
            "failed to symlink {} -> {}",
            init_path.display(),
            rel_target
        )
    })?;

    eprintln!(
        "created init symlink: {} -> {}",
        init_path
            .strip_prefix(mount)
            .unwrap_or(&init_path)
            .display(),
        systemd_path,
    );

    Ok(())
}

/// Enable serial console login via serial-getty@ttyS0.service.
///
/// The upstream `serial-getty@.service` template has `BindsTo=dev-%i.device`,
/// which requires udev to tag the device before the getty starts. Rootfs
/// images imported for nspawn use typically lack `systemd-udevd`, so the
/// device unit never activates and boot hangs. We replace the template at
/// `/etc/systemd/system/` (highest priority) with a copy that drops the
/// device dependency, and explicitly enable the ttyS0 instance.
pub(super) fn enable_serial_console(mount: &Path) -> Result<()> {
    let unit_dir = mount.join("etc/systemd/system");
    fs::create_dir_all(&unit_dir)
        .with_context(|| format!("failed to create {}", unit_dir.display()))?;

    // Copy the distro's serial-getty@ template and strip the BindsTo=dev-%i
    // dependency. Container-imported rootfs images lack udev, so the device
    // unit never activates and boot hangs. Copying preserves the distro's
    // agetty flags, TERM handling, and credential imports (systemd 257+).
    let src_template = mount.join("lib/systemd/system/serial-getty@.service");
    let src_template = if src_template.is_file() {
        src_template
    } else {
        mount.join("usr/lib/systemd/system/serial-getty@.service")
    };
    let dst_template = unit_dir.join("serial-getty@.service");

    if src_template.is_file() {
        let content = fs::read_to_string(&src_template)
            .with_context(|| format!("failed to read {}", src_template.display()))?;
        let patched: String = content
            .lines()
            .filter(|line| {
                // Remove BindsTo=dev-*.device entirely.
                !line.trim().starts_with("BindsTo=dev-")
            })
            .map(|line| {
                // Strip dev-*.device tokens from After= lines, keep the rest.
                if line.trim().starts_with("After=") && line.contains("dev-") {
                    let Some((key, vals)) = line.split_once('=') else {
                        return line.to_string();
                    };
                    let filtered: Vec<&str> = vals
                        .split_whitespace()
                        .filter(|v| !v.starts_with("dev-"))
                        .collect();
                    if filtered.is_empty() {
                        String::new()
                    } else {
                        format!("{key}={}", filtered.join(" "))
                    }
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&dst_template, patched.as_bytes())
            .with_context(|| format!("failed to write {}", dst_template.display()))?;
    } else {
        // Fallback: write a minimal template if the distro doesn't ship one.
        fs::write(
            &dst_template,
            "\
[Unit]
Description=Serial Getty on %I
After=systemd-user-sessions.service plymouth-quit-wait.service getty-pre.target
Before=getty.target
IgnoreOnIsolate=yes

[Service]
ExecStart=-/sbin/agetty -o '-- \\\\u' --noreset --noclear --keep-baud 115200,57600,38400,9600 - $TERM
Type=idle
Restart=always
UtmpIdentifier=%I
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/%I
TTYReset=yes
TTYVHangup=yes
IgnoreSIGPIPE=no
SendSIGHUP=yes

[Install]
WantedBy=getty.target
",
        )
        .with_context(|| format!("failed to write {}", dst_template.display()))?;
    }

    // Explicitly enable serial-getty@ttyS0 so it starts even if the getty
    // generator is absent or non-functional.
    let wants_dir = unit_dir.join("getty.target.wants");
    fs::create_dir_all(&wants_dir)
        .with_context(|| format!("failed to create {}", wants_dir.display()))?;

    let link = wants_dir.join("serial-getty@ttyS0.service");
    if link.symlink_metadata().is_err() {
        std::os::unix::fs::symlink("/etc/systemd/system/serial-getty@.service", &link)
            .with_context(|| format!("failed to create symlink {}", link.display()))?;
    }

    // Ensure serial-getty@ttyS0 is pulled in by multi-user.target. Container
    // images often omit getty.target from multi-user.target.wants/ since
    // containers don't need login gettys. Going through getty.target via
    // drop-ins doesn't work reliably on all systemd versions (e.g. systemd 257
    // on AlmaLinux 10 ignores drop-in Wants=getty.target). Directly wanting
    // the serial-getty instance from multi-user.target bypasses that entirely.
    let dropin_dir = unit_dir.join("multi-user.target.d");
    fs::create_dir_all(&dropin_dir)
        .with_context(|| format!("failed to create {}", dropin_dir.display()))?;

    let dropin = dropin_dir.join("wants-getty.conf");
    fs::write(&dropin, "[Unit]\nWants=serial-getty@ttyS0.service\n")
        .with_context(|| format!("failed to write {}", dropin.display()))?;

    Ok(())
}

/// Write /etc/fstab with the root device entry.
pub(super) fn write_vm_fstab(mount: &Path, fs_type: RawFs, swap_size: u64) -> Result<()> {
    let fstab = mount.join("etc/fstab");
    let mut content = format!("/dev/vda1 / {fs_type} defaults 0 1\n");
    if swap_size > 0 {
        content.push_str("/dev/vda2 none swap sw 0 0\n");
    }
    fs::write(&fstab, content).with_context(|| format!("failed to write {}", fstab.display()))
}

/// Write /etc/hostname with the given hostname.
pub(super) fn write_hostname(mount: &Path, hostname: &str) -> Result<()> {
    let path = mount.join("etc/hostname");
    fs::write(&path, format!("{hostname}\n"))
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Unmask systemd-resolved if it is masked (symlink to /dev/null).
pub(super) fn unmask_resolved(mount: &Path) -> Result<()> {
    let resolved = mount.join("etc/systemd/system/systemd-resolved.service");
    if resolved.exists() || resolved.symlink_metadata().is_ok() {
        // Check if it's a symlink to /dev/null (masked).
        if let Ok(target) = fs::read_link(&resolved) {
            if target.to_str() == Some("/dev/null") {
                fs::remove_file(&resolved).with_context(|| {
                    format!(
                        "failed to unmask systemd-resolved at {}",
                        resolved.display()
                    )
                })?;
            }
        }
    }
    Ok(())
}

/// Copy the host's /etc/resolv.conf into the mounted rootfs.
pub(super) fn copy_host_resolv_conf(mount: &Path) -> Result<()> {
    let host_resolv = Path::new("/etc/resolv.conf");
    let content = fs::read_to_string(host_resolv)
        .with_context(|| format!("failed to read {}", host_resolv.display()))?;
    let resolv = mount.join("etc/resolv.conf");
    // Remove if it's a symlink (e.g. to ../run/systemd/resolve/stub-resolv.conf).
    if resolv.symlink_metadata().is_ok() {
        let _ = fs::remove_file(&resolv);
    }
    fs::write(&resolv, content).with_context(|| format!("failed to write {}", resolv.display()))
}

/// Write /etc/resolv.conf with the given nameservers.
pub(super) fn write_resolv_conf(mount: &Path, nameservers: &[String]) -> Result<()> {
    for ns in nameservers {
        if ns.parse::<std::net::IpAddr>().is_err() {
            bail!("invalid DNS nameserver: {ns}");
        }
    }
    let resolv = mount.join("etc/resolv.conf");
    // Remove if it's a symlink (e.g. to ../run/systemd/resolve/stub-resolv.conf).
    if resolv.symlink_metadata().is_ok() {
        let _ = fs::remove_file(&resolv);
    }
    let content: String = nameservers
        .iter()
        .map(|ns| format!("nameserver {ns}\n"))
        .collect();
    fs::write(&resolv, content).with_context(|| format!("failed to write {}", resolv.display()))
}

/// Configure systemd-networkd for DHCP on network interfaces.
pub(super) fn configure_networkd(mount: &Path, net_ifaces: u32) -> Result<()> {
    let network_dir = mount.join("etc/systemd/network");
    fs::create_dir_all(&network_dir)
        .with_context(|| format!("failed to create {}", network_dir.display()))?;

    let match_names = if net_ifaces == 1 {
        "en* eth*".to_string()
    } else {
        // For multiple interfaces, match all common names.
        "en* eth*".to_string()
    };

    let content = format!("[Match]\nName={match_names}\n\n[Network]\nDHCP=yes\n");
    let network_file = network_dir.join("80-vm-dhcp.network");
    fs::write(&network_file, content)
        .with_context(|| format!("failed to write {}", network_file.display()))?;

    // Enable systemd-networkd.service via symlink.
    let system_dir = mount.join("etc/systemd/system");
    fs::create_dir_all(&system_dir)?;

    let wants_dir = system_dir.join("multi-user.target.wants");
    fs::create_dir_all(&wants_dir)?;

    let link = wants_dir.join("systemd-networkd.service");
    if !link.exists() {
        std::os::unix::fs::symlink("/lib/systemd/system/systemd-networkd.service", &link)
            .with_context(|| format!("failed to enable systemd-networkd at {}", link.display()))?;
    }

    Ok(())
}

/// Set the root password in /etc/shadow.
pub(super) fn set_root_password(mount: &Path, password: &str) -> Result<()> {
    let shadow = mount.join("etc/shadow");
    let content = fs::read_to_string(&shadow)
        .with_context(|| format!("failed to read {}", shadow.display()))?;

    let hash = if password.is_empty() {
        String::new()
    } else {
        sha512_crypt(password)?
    };

    let mut found = false;
    let new_content: String = content
        .lines()
        .map(|line| {
            if line.starts_with("root:") {
                let parts: Vec<&str> = line.splitn(3, ':').collect();
                found = true;
                if parts.len() >= 3 {
                    format!("root:{hash}:{}", parts[2])
                } else {
                    format!("root:{hash}:")
                }
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    if !found {
        bail!("root entry not found in {}", shadow.display());
    }

    // Preserve trailing newline.
    let new_content = if content.ends_with('\n') && !new_content.ends_with('\n') {
        new_content + "\n"
    } else {
        new_content
    };

    fs::write(&shadow, new_content).with_context(|| format!("failed to write {}", shadow.display()))
}

/// Install an SSH public key for root.
pub(super) fn install_ssh_key(mount: &Path, key: &str) -> Result<()> {
    let ssh_dir = mount.join("root/.ssh");
    fs::create_dir_all(&ssh_dir)
        .with_context(|| format!("failed to create {}", ssh_dir.display()))?;
    fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700))?;

    let auth_keys = ssh_dir.join("authorized_keys");
    let content = if key.ends_with('\n') {
        key.to_string()
    } else {
        format!("{key}\n")
    };
    fs::write(&auth_keys, content)
        .with_context(|| format!("failed to write {}", auth_keys.display()))?;
    fs::set_permissions(&auth_keys, fs::Permissions::from_mode(0o600))?;

    Ok(())
}

// --- SHA-512 crypt implementation ($6$) ---

const CRYPT_B64_CHARS: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Compute a SHA-512 crypt hash ($6$salt$hash) for the given password.
pub(super) fn sha512_crypt(password: &str) -> Result<String> {
    let mut salt_bytes = [0u8; 16];
    let mut f = File::open("/dev/urandom").context("failed to open /dev/urandom")?;
    f.read_exact(&mut salt_bytes)?;

    // Encode salt using the crypt base64 alphabet.
    let salt: String = salt_bytes
        .iter()
        .map(|b| CRYPT_B64_CHARS[(*b as usize) % CRYPT_B64_CHARS.len()] as char)
        .collect();

    let hash = sha512_crypt_hash(password.as_bytes(), salt.as_bytes(), 5000);
    Ok(format!("$6${salt}${hash}"))
}

/// Core SHA-512 crypt algorithm (Drepper specification, 5000 default rounds).
pub(super) fn sha512_crypt_hash(password: &[u8], salt: &[u8], rounds: u32) -> String {
    use sha2::{Digest, Sha512};

    // Compute digest B: sha512(password + salt + password)
    let mut ctx_b = Sha512::new();
    ctx_b.update(password);
    ctx_b.update(salt);
    ctx_b.update(password);
    let digest_b = ctx_b.finalize();

    // Compute digest A: sha512(password + salt + <bytes from B based on password length>)
    let mut ctx_a = Sha512::new();
    ctx_a.update(password);
    ctx_a.update(salt);

    // Add bytes from digest B, password.len() bytes total.
    let mut n = password.len();
    while n >= 64 {
        ctx_a.update(&digest_b[..]);
        n -= 64;
    }
    if n > 0 {
        ctx_a.update(&digest_b[..n]);
    }

    // Process password length bits.
    let mut length = password.len();
    while length > 0 {
        if length & 1 != 0 {
            ctx_a.update(&digest_b[..]);
        } else {
            ctx_a.update(password);
        }
        length >>= 1;
    }

    let mut digest_a = ctx_a.finalize();

    // Compute digest P: sha512(password repeated password.len() times)
    let mut ctx_p = Sha512::new();
    for _ in 0..password.len() {
        ctx_p.update(password);
    }
    let digest_p = ctx_p.finalize();

    // Produce P-string: password.len() bytes from digest_p.
    let mut p_bytes = Vec::with_capacity(password.len());
    let mut remaining = password.len();
    while remaining >= 64 {
        p_bytes.extend_from_slice(&digest_p[..]);
        remaining -= 64;
    }
    if remaining > 0 {
        p_bytes.extend_from_slice(&digest_p[..remaining]);
    }

    // Compute digest S: sha512(salt repeated (16 + digest_a[0]) times)
    let mut ctx_s = Sha512::new();
    let repeat_count = 16 + (digest_a[0] as usize);
    for _ in 0..repeat_count {
        ctx_s.update(salt);
    }
    let digest_s = ctx_s.finalize();

    // Produce S-string: salt.len() bytes from digest_s.
    let mut s_bytes = Vec::with_capacity(salt.len());
    let mut remaining = salt.len();
    while remaining >= 64 {
        s_bytes.extend_from_slice(&digest_s[..]);
        remaining -= 64;
    }
    if remaining > 0 {
        s_bytes.extend_from_slice(&digest_s[..remaining]);
    }

    // Rounds.
    for i in 0..rounds {
        let mut ctx = Sha512::new();
        if i & 1 != 0 {
            ctx.update(&p_bytes);
        } else {
            ctx.update(&digest_a[..]);
        }
        if i % 3 != 0 {
            ctx.update(&s_bytes);
        }
        if i % 7 != 0 {
            ctx.update(&p_bytes);
        }
        if i & 1 != 0 {
            ctx.update(&digest_a[..]);
        } else {
            ctx.update(&p_bytes);
        }
        digest_a = ctx.finalize();
    }

    // Encode the final digest with crypt-specific base64 and SHA-512 byte reordering.
    crypt_b64_encode(&digest_a)
}

/// Encode 64 bytes of SHA-512 digest using crypt-specific base64 with
/// the SHA-512 byte reordering from the Drepper specification.
fn crypt_b64_encode(hash: &[u8]) -> String {
    let mut out = String::with_capacity(86);

    // SHA-512 crypt byte reordering: groups of 3 bytes (with specific indices).
    let groups: [(usize, usize, usize); 21] = [
        (0, 21, 42),
        (22, 43, 1),
        (44, 2, 23),
        (3, 24, 45),
        (25, 46, 4),
        (47, 5, 26),
        (6, 27, 48),
        (28, 49, 7),
        (50, 8, 29),
        (9, 30, 51),
        (31, 52, 10),
        (53, 11, 32),
        (12, 33, 54),
        (34, 55, 13),
        (56, 14, 35),
        (15, 36, 57),
        (37, 58, 16),
        (59, 17, 38),
        (18, 39, 60),
        (40, 61, 19),
        (62, 20, 41),
    ];

    for (a, b, c) in groups {
        let v = ((hash[a] as u32) << 16) | ((hash[b] as u32) << 8) | (hash[c] as u32);
        for i in 0..4 {
            out.push(CRYPT_B64_CHARS[((v >> (i * 6)) & 0x3f) as usize] as char);
        }
    }

    // Final byte (index 63), only 2 characters.
    let v = hash[63] as u32;
    for i in 0..2 {
        out.push(CRYPT_B64_CHARS[((v >> (i * 6)) & 0x3f) as usize] as char);
    }

    out
}
