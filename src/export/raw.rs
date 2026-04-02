//! Raw disk image export: bare and GPT-partitioned ext4/btrfs images.

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::{set_timezone, ExportOptions, ExportResult, RawFs};
use crate::{check_interrupted, copy, system_check};

/// Export by creating a raw disk image with the specified filesystem.
pub(super) fn export_to_raw(
    src: &Path,
    output: &Path,
    fs_type: RawFs,
    opts: &ExportOptions<'_>,
) -> Result<ExportResult> {
    let free_space = opts.free_space;
    let verbose = opts.verbose;
    let vm_opts = opts.vm_opts;
    if output.exists() {
        if opts.force {
            fs::remove_file(output)
                .with_context(|| format!("failed to remove {}", output.display()))?;
        } else {
            bail!("destination already exists: {}", output.display());
        }
    }

    let (mkfs_bin, mkfs_pkg) = match fs_type {
        RawFs::Ext4 => ("mkfs.ext4", "e2fsprogs"),
        RawFs::Btrfs => ("mkfs.btrfs", "btrfs-progs"),
    };
    let mut deps: Vec<(&str, &str)> = vec![(mkfs_bin, mkfs_pkg)];
    if vm_opts.is_some() {
        deps.push(("sfdisk", "util-linux"));
    }
    let swap_size = vm_opts.map(|o| o.swap_size).unwrap_or(0);
    if swap_size > 0 {
        deps.push(("mkswap", "util-linux"));
    }
    system_check::check_dependencies(&deps, verbose)?;

    // Calculate or parse image size.
    let mut image_size = match opts.size {
        Some(s) => crate::parse_size(s)?,
        None => {
            let total = dir_size(src)?;
            // At least 256 MiB, otherwise 150% of content for filesystem
            // metadata overhead, plus guaranteed free space.
            let min_size = 256 * 1024 * 1024;
            let padded = (total as f64 * 1.5) as u64 + free_space;
            std::cmp::max(min_size, padded)
        }
    };

    // VM exports use a GPT partition table; add 2 MiB for the protective MBR,
    // primary GPT header, partition alignment gap, and backup GPT header.
    // Swap partition size (if any) is added on top.
    let is_vm = vm_opts.is_some();
    if is_vm {
        image_size += 2 * 1024 * 1024;
        if swap_size > 0 {
            // Add swap partition size plus 1 MiB alignment padding.
            image_size += swap_size + 1024 * 1024;
        }
    }

    if verbose {
        eprintln!(
            "creating {fs_type} raw image: {} ({} bytes)",
            output.display(),
            image_size
        );
    }

    // Create sparse file.
    let file =
        File::create(output).with_context(|| format!("failed to create {}", output.display()))?;
    file.set_len(image_size)
        .with_context(|| format!("failed to set file size for {}", output.display()))?;
    drop(file);

    let run_dir = Path::new("/run/sdme");
    if !run_dir.exists() {
        fs::create_dir_all(run_dir).context("failed to create /run/sdme")?;
        fs::set_permissions(run_dir, fs::Permissions::from_mode(0o700))
            .context("failed to set permissions on /run/sdme")?;
    }
    let mount_dir = run_dir.join(format!("export-mount-{}", std::process::id()));

    // VM exports: GPT partition table via sfdisk, then losetup --partscan.
    // Non-VM exports: bare filesystem on the whole image file.
    let copy_result = if is_vm {
        export_raw_gpt(output, &mount_dir, mkfs_bin, fs_type, src, opts)
    } else {
        export_raw_bare(output, &mount_dir, mkfs_bin, fs_type, src, opts)
    };

    if let Err(e) = copy_result {
        let _ = fs::remove_file(output);
        return Err(e).context("failed to copy to raw image");
    }

    // Align to 512-byte sector boundary (benefits all raw exports).
    align_disk_image(output)?;

    // Re-read actual file size after alignment.
    let output_size = fs::metadata(output)
        .with_context(|| format!("failed to stat {}", output.display()))?
        .len();

    let num_partitions = if is_vm {
        if swap_size > 0 {
            2
        } else {
            1
        }
    } else {
        0
    };
    Ok(ExportResult {
        output_size,
        free_space: Some(free_space),
        partitions: Some(num_partitions),
    })
}

/// RAII guard for a loop device. Detaches on drop.
struct LoopGuard {
    device: std::path::PathBuf,
    active: bool,
}

impl LoopGuard {
    fn new() -> Self {
        Self {
            device: std::path::PathBuf::new(),
            active: false,
        }
    }

    fn set_active(&mut self, device: std::path::PathBuf) {
        self.device = device;
        self.active = true;
    }

    fn detach(&mut self) {
        if self.active {
            let _ = std::process::Command::new("losetup")
                .args(["--detach"])
                .arg(&self.device)
                .status();
            self.active = false;
        }
    }
}

impl Drop for LoopGuard {
    fn drop(&mut self) {
        self.detach();
    }
}

/// Export a bare (unpartitioned) raw disk image. The entire image is one filesystem.
fn export_raw_bare(
    output: &Path,
    mount_dir: &Path,
    mkfs_bin: &str,
    fs_type: RawFs,
    src: &Path,
    opts: &ExportOptions,
) -> Result<()> {
    let (mkfs_args, mkfs_err): (&[&str], &str) = match fs_type {
        RawFs::Ext4 => (&["-q", "-F"], "mkfs.ext4 failed"),
        RawFs::Btrfs => (&["-q", "-f"], "mkfs.btrfs failed"),
    };
    let status = std::process::Command::new(mkfs_bin)
        .args(mkfs_args)
        .arg(output)
        .status()
        .with_context(|| format!("failed to run {mkfs_bin}"))?;
    crate::check_interrupted()?;
    if !status.success() {
        bail!("{mkfs_err}");
    }

    fs::create_dir_all(mount_dir)
        .with_context(|| format!("failed to create mount point {}", mount_dir.display()))?;

    let mount_status = std::process::Command::new("mount")
        .args(["-o", "loop"])
        .arg(output)
        .arg(mount_dir)
        .status()
        .context("failed to run mount")?;
    crate::check_interrupted()?;
    if !mount_status.success() {
        let _ = fs::remove_dir(mount_dir);
        bail!("failed to mount raw image");
    }

    if fs_type == RawFs::Ext4 {
        let lost_found = mount_dir.join("lost+found");
        if lost_found.exists() {
            let _ = fs::remove_dir(&lost_found);
        }
    }

    let result = (|| -> Result<()> {
        copy::copy_metadata(src, mount_dir)?;
        copy::copy_tree(src, mount_dir, opts.verbose)?;
        if let Some(tz) = opts.timezone {
            set_timezone(mount_dir, tz)?;
        }
        Ok(())
    })();

    unmount_and_cleanup(mount_dir);
    result
}

/// Export a GPT-partitioned raw disk image for VM boot.
///
/// Creates a GPT partition table with a Linux root partition starting at
/// 1 MiB (standard alignment), and optionally a swap partition. The
/// filesystem lives on the partition, not the whole device. This avoids
/// sector 0 conflicts with hypervisors like cloud-hypervisor.
fn export_raw_gpt(
    output: &Path,
    mount_dir: &Path,
    mkfs_bin: &str,
    fs_type: RawFs,
    src: &Path,
    opts: &ExportOptions,
) -> Result<()> {
    let vm_opts = opts.vm_opts;
    let verbose = opts.verbose;
    let swap_size = vm_opts.map(|o| o.swap_size).unwrap_or(0);

    // Write a GPT partition table. When swap is requested, the root
    // partition is sized to fill everything except the swap area, and a
    // second partition of type=swap gets the remainder.
    let sfdisk_input = if swap_size > 0 {
        let swap_mib = swap_size / (1024 * 1024);
        format!("label: gpt\ntype=linux\ntype=swap, size={swap_mib}MiB\n")
    } else {
        "label: gpt\ntype=linux\n".to_string()
    };
    let mut sfdisk = std::process::Command::new("sfdisk")
        .arg("--quiet")
        .arg(output)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(if verbose {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::null()
        })
        .spawn()
        .context("failed to run sfdisk")?;
    {
        use std::io::Write;
        sfdisk
            .stdin
            .take()
            .context("sfdisk stdin unavailable")?
            .write_all(sfdisk_input.as_bytes())
            .context("failed to write to sfdisk stdin")?;
    }
    let sfdisk_status = sfdisk.wait().context("failed to wait for sfdisk")?;
    if !sfdisk_status.success() {
        bail!("sfdisk failed to create GPT partition table");
    }

    // Attach via losetup with partition scanning.
    let lo_output = std::process::Command::new("losetup")
        .args(["--partscan", "--find", "--show"])
        .arg(output)
        .output()
        .context("failed to run losetup")?;
    crate::check_interrupted()?;
    if !lo_output.status.success() {
        let stderr = String::from_utf8_lossy(&lo_output.stderr);
        bail!("losetup failed: {stderr}");
    }
    let loop_str = String::from_utf8_lossy(&lo_output.stdout)
        .trim()
        .to_string();
    if !loop_str.starts_with("/dev/loop")
        || !loop_str["/dev/loop".len()..]
            .chars()
            .all(|c| c.is_ascii_digit())
    {
        bail!("unexpected losetup output: {loop_str}");
    }
    let loop_dev = std::path::PathBuf::from(loop_str);

    let mut loop_guard = LoopGuard::new();
    loop_guard.set_active(loop_dev.clone());

    if verbose {
        eprintln!("attached loop device: {}", loop_dev.display());
    }

    // Wait for the kernel to create the partition device (e.g. /dev/loop0p1).
    let part_dev = std::path::PathBuf::from(format!("{}p1", loop_dev.display()));
    wait_for_partition(&part_dev)?;

    if verbose {
        eprintln!("partition device: {}", part_dev.display());
    }

    // Format the root partition.
    let (mkfs_args, mkfs_err): (&[&str], &str) = match fs_type {
        RawFs::Ext4 => (&["-q", "-F"], "mkfs.ext4 failed"),
        RawFs::Btrfs => (&["-q", "-f"], "mkfs.btrfs failed"),
    };
    let status = std::process::Command::new(mkfs_bin)
        .args(mkfs_args)
        .arg(&part_dev)
        .status()
        .with_context(|| format!("failed to run {mkfs_bin}"))?;
    crate::check_interrupted()?;
    if !status.success() {
        bail!("{mkfs_err}");
    }

    // Format the swap partition if requested.
    if swap_size > 0 {
        let swap_dev = std::path::PathBuf::from(format!("{}p2", loop_dev.display()));
        wait_for_partition(&swap_dev)?;
        if verbose {
            eprintln!("swap partition device: {}", swap_dev.display());
        }
        let status = std::process::Command::new("mkswap")
            .arg(&swap_dev)
            .status()
            .context("failed to run mkswap")?;
        crate::check_interrupted()?;
        if !status.success() {
            bail!("mkswap failed");
        }
    }

    // Mount the root partition.
    fs::create_dir_all(mount_dir)
        .with_context(|| format!("failed to create mount point {}", mount_dir.display()))?;

    let mount_status = std::process::Command::new("mount")
        .arg(&part_dev)
        .arg(mount_dir)
        .status()
        .context("failed to run mount")?;
    crate::check_interrupted()?;
    if !mount_status.success() {
        let _ = fs::remove_dir(mount_dir);
        bail!("failed to mount partition {}", part_dev.display());
    }

    // Remove lost+found created by mkfs.ext4.
    if fs_type == RawFs::Ext4 {
        let lost_found = mount_dir.join("lost+found");
        if lost_found.exists() {
            let _ = fs::remove_dir(&lost_found);
        }
    }

    let result = (|| -> Result<()> {
        copy::copy_metadata(src, mount_dir)?;
        copy::copy_tree(src, mount_dir, verbose)?;
        if let Some(opts) = vm_opts {
            super::vm::prep_vm_rootfs(mount_dir, fs_type, opts, verbose)?;
        }
        if let Some(tz) = opts.timezone {
            set_timezone(mount_dir, tz)?;
        }
        Ok(())
    })();

    // Unmount, then detach loop device (order matters).
    unmount_and_cleanup(mount_dir);
    loop_guard.detach();

    result
}

/// Wait for a partition device node to appear (up to 2 seconds).
fn wait_for_partition(dev: &Path) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !dev.exists() {
        if std::time::Instant::now() >= deadline {
            bail!(
                "partition device {} did not appear within 2 seconds",
                dev.display()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(())
}

/// Unmount a mount point (recursive) and remove the directory.
pub(super) fn unmount_and_cleanup(mount_dir: &Path) {
    match std::process::Command::new("umount")
        .arg("-R")
        .arg(mount_dir)
        .status()
    {
        Ok(s) if !s.success() => {
            eprintln!("warning: failed to unmount {}", mount_dir.display());
        }
        Err(e) => {
            eprintln!("warning: failed to unmount {}: {e}", mount_dir.display());
        }
        _ => {}
    }
    let _ = fs::remove_dir(mount_dir);
}

/// Recursively walk a directory tree summing regular file sizes.
pub(super) fn dir_size(path: &Path) -> Result<u64> {
    let mut total: u64 = 0;
    let entries = fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?;
    for entry in entries {
        check_interrupted()?;
        let entry = entry.with_context(|| format!("failed to read entry in {}", path.display()))?;
        let meta = fs::symlink_metadata(entry.path())
            .with_context(|| format!("failed to stat {}", entry.path().display()))?;
        if meta.is_dir() {
            total += dir_size(&entry.path())?;
        } else if meta.is_file() {
            // Round up to 4K block boundary to match ext4/btrfs allocation.
            // Without this, rootfs with many small files (e.g. NixOS /nix/store)
            // produce undersized images.
            total += (meta.len() + 4095) & !4095;
        }
        // Symlinks, sockets, etc: skip (zero on-disk size contribution).
    }
    Ok(total)
}

/// Align a raw disk image to a 512-byte sector boundary.
pub(super) fn align_disk_image(path: &Path) -> Result<()> {
    let size = fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?
        .len();
    let remainder = size % 512;
    if remainder != 0 {
        let aligned = size + (512 - remainder);
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("failed to open {} for alignment", path.display()))?
            .set_len(aligned)
            .with_context(|| format!("failed to align {}", path.display()))?;
    }
    Ok(())
}
