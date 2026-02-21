//! Internal API for managing root filesystems used as overlayfs lower layers.
//!
//! Provides functions for importing, listing, and removing root filesystems
//! stored under `{datadir}/rootfs/{name}/`. Each rootfs is a complete
//! directory tree that containers reference via their state file.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs as unix_fs;
use std::os::unix::io::FromRawFd;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{State, validate_name};

/// Parse a `/etc/subuid` or `/etc/subgid` file and return `(start, count)` for `username`.
///
/// The file format is `username:start:count` per line. Comments (starting with `#`)
/// and blank lines are skipped. Returns the first matching entry.
fn parse_subid_file(path: &Path, username: &str) -> Result<(u64, u64)> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        if parts[0] == username {
            let start: u64 = parts[1]
                .parse()
                .with_context(|| format!("invalid start in {}: {}", path.display(), line))?;
            let count: u64 = parts[2]
                .parse()
                .with_context(|| format!("invalid count in {}: {}", path.display(), line))?;
            return Ok((start, count));
        }
    }
    bail!(
        "no subordinate IDs for user '{}' in {}; run: sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 {}",
        username,
        path.display(),
        username
    );
}

/// Check that `newuidmap` and `newgidmap` binaries exist on PATH.
fn check_subid_helpers() -> Result<()> {
    for helper in ["newuidmap", "newgidmap"] {
        match std::process::Command::new(helper).arg("--version").output() {
            Ok(_) => {} // exists (exit code doesn't matter, --version may not be supported)
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!(
                    "{helper} not found; install the uidmap package (e.g. apt install uidmap)"
                );
            }
            Err(e) => {
                return Err(e).with_context(|| format!("failed to check for {helper}"));
            }
        }
    }
    Ok(())
}

/// An entry returned by [`list`].
pub struct RootfsEntry {
    pub name: String,
    pub distro: String,
}

/// Parse an `os-release` file into a key-value map.
///
/// Reads `{rootfs}/etc/os-release`, falling back to
/// `{rootfs}/usr/lib/os-release` per the freedesktop spec.
/// Returns an empty map if neither file exists.
fn parse_os_release(rootfs: &Path) -> HashMap<String, String> {
    let primary = rootfs.join("etc/os-release");
    let fallback = rootfs.join("usr/lib/os-release");

    let content = match fs::read_to_string(&primary) {
        Ok(c) => c,
        Err(_) => match fs::read_to_string(&fallback) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        },
    };

    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim();
            // Strip surrounding double quotes if present.
            let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                &value[1..value.len() - 1]
            } else {
                value
            };
            map.insert(key.trim().to_string(), value.to_string());
        }
    }
    map
}

/// Detect the distro name from `os-release` inside a rootfs.
///
/// Returns `PRETTY_NAME` if present, else `NAME`, else an empty string.
fn detect_distro(rootfs: &Path) -> String {
    let map = parse_os_release(rootfs);
    if let Some(v) = map.get("PRETTY_NAME") {
        return v.clone();
    }
    if let Some(v) = map.get("NAME") {
        return v.clone();
    }
    String::new()
}

/// List all imported root filesystems under `{datadir}/rootfs/`.
///
/// Returns entries sorted by name. If no rootfs directory exists,
/// returns an empty vec (not an error).
pub fn list(datadir: &Path) -> Result<Vec<RootfsEntry>> {
    let rootfs_dir = datadir.join("rootfs");
    if !rootfs_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&rootfs_dir)
        .with_context(|| format!("failed to read {}", rootfs_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();

        // Skip hidden entries (staging dirs like .foo.importing, meta files).
        if name.starts_with('.') {
            continue;
        }

        if !entry.file_type()?.is_dir() {
            continue;
        }

        // Try sidecar metadata first; fall back to live detection.
        let meta_path = rootfs_dir.join(format!(".{name}.meta"));
        let distro = if meta_path.exists() {
            State::read_from(&meta_path)
                .ok()
                .and_then(|s| s.get("DISTRO").map(|v| v.to_string()))
                .unwrap_or_default()
        } else {
            detect_distro(&entry.path())
        };

        entries.push(RootfsEntry { name, distro });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Import a root filesystem from a source directory.
///
/// The source must be an existing directory (e.g. debootstrap output).
/// The import is transactional: files are copied into a staging directory
/// and atomically renamed into place on success.
pub fn import(datadir: &Path, source: &Path, name: &str, verbose: bool, privileged: bool, force: bool) -> Result<()> {
    validate_name(name)?;

    // Phase 1: only directory imports are supported.
    // TODO: qcow2 support
    // TODO: raw disk image support
    // TODO: tarball support (.tar, .tar.gz, .tar.bz2, .tar.xz)
    if !source.is_dir() {
        if !source.exists() {
            bail!("source path does not exist: {}", source.display());
        }
        bail!("source path is not a directory: {}", source.display());
    }

    let rootfs_dir = datadir.join("rootfs");
    let final_dir = rootfs_dir.join(name);
    if final_dir.exists() {
        if !force {
            bail!("rootfs already exists: {name}; re-run with -f to replace it");
        }
        if verbose {
            eprintln!("removing existing rootfs '{name}' (forced)");
        }
        let _ = make_removable(&final_dir);
        fs::remove_dir_all(&final_dir)
            .with_context(|| format!("failed to remove existing rootfs {}", final_dir.display()))?;
        let meta_path = rootfs_dir.join(format!(".{name}.meta"));
        let _ = fs::remove_file(meta_path);
    }

    let staging_name = format!(".{name}.importing");
    let staging_dir = rootfs_dir.join(&staging_name);

    // Clean up any leftover staging dir from a previous failed attempt.
    cleanup_staging(&staging_dir, force, verbose)?;

    fs::create_dir_all(&rootfs_dir)
        .with_context(|| format!("failed to create {}", rootfs_dir.display()))?;

    match do_import(source, &staging_dir, verbose, privileged) {
        Ok(()) => {
            fs::rename(&staging_dir, &final_dir).with_context(|| {
                format!(
                    "failed to rename {} to {}",
                    staging_dir.display(),
                    final_dir.display()
                )
            })?;

            // Write distro metadata sidecar.
            let distro = detect_distro(&final_dir);
            let mut meta = State::new();
            meta.set("DISTRO", &distro);
            let meta_path = rootfs_dir.join(format!(".{name}.meta"));
            meta.write_to(&meta_path)?;

            if verbose {
                eprintln!("imported rootfs '{}' from {}", name, source.display());
            }
            Ok(())
        }
        Err(e) => {
            // Make a best effort to remove the staging dir. Some entries
            // may have restrictive permissions that prevent removal, so
            // fix permissions recursively before the final cleanup.
            let _ = make_removable(&staging_dir);
            let _ = fs::remove_dir_all(&staging_dir);
            Err(e)
        }
    }
}

/// Import a root filesystem from a tar stream using a user namespace.
///
/// When `tar_path` is `None`, reads from stdin (e.g. piped from `sudo tar cf -`).
/// When `tar_path` is `Some`, reads from the given tar file.
///
/// Forks into a new user+mount namespace where the calling user is mapped to
/// root (UID/GID 0), mounts an empty overlayfs, and extracts the tar stream
/// into it. The overlay upper directory becomes the final rootfs.
///
/// This allows unprivileged users to import rootfs tarballs that contain files
/// owned by root, which would otherwise be inaccessible after extraction.
pub fn import_tar(datadir: &Path, name: &str, tar_path: Option<&Path>, verbose: bool, force: bool) -> Result<()> {
    validate_name(name)?;

    // Ensure the tar binary is available before doing any work.
    check_tar_available()?;

    if verbose {
        match tar_path {
            Some(p) => eprintln!("importing rootfs '{name}' from {}", p.display()),
            None => eprintln!("importing rootfs '{name}' from stdin tar stream"),
        }
    }

    let rootfs_dir = datadir.join("rootfs");
    let final_dir = rootfs_dir.join(name);
    if final_dir.exists() {
        if !force {
            bail!("rootfs already exists: {name}; re-run with -f to replace it");
        }
        if verbose {
            eprintln!("removing existing rootfs '{name}' (forced)");
        }
        let _ = make_removable(&final_dir);
        fs::remove_dir_all(&final_dir)
            .with_context(|| format!("failed to remove existing rootfs {}", final_dir.display()))?;
        let meta_path = rootfs_dir.join(format!(".{name}.meta"));
        let _ = fs::remove_file(meta_path);
    }

    let staging_name = format!(".{name}.importing");
    let staging_dir = rootfs_dir.join(&staging_name);

    // Clean up any leftover staging dir from a previous failed attempt.
    cleanup_staging(&staging_dir, force, verbose)?;

    fs::create_dir_all(&rootfs_dir)
        .with_context(|| format!("failed to create {}", rootfs_dir.display()))?;

    // Create staging subdirectories for overlayfs.
    let lower_dir = staging_dir.join("lower");
    let upper_dir = staging_dir.join("upper");
    let work_dir = staging_dir.join("work");
    let merged_dir = staging_dir.join("merged");
    for dir in [&staging_dir, &lower_dir, &upper_dir, &work_dir, &merged_dir] {
        fs::create_dir(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }

    if verbose {
        eprintln!("created staging directory: {}", staging_dir.display());
    }

    // Look up current username and parse subordinate UID/GID ranges (before fork).
    let real_uid = unsafe { libc::getuid() };
    let real_gid = unsafe { libc::getgid() };

    let username = {
        let pw = unsafe { libc::getpwuid(real_uid) };
        if pw.is_null() {
            bail!("failed to look up username for uid {real_uid}");
        }
        unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }
            .to_str()
            .context("username is not valid UTF-8")?
            .to_string()
    };

    let (subuid_start, subuid_count) = parse_subid_file(Path::new("/etc/subuid"), &username)?;
    let (subgid_start, subgid_count) = parse_subid_file(Path::new("/etc/subgid"), &username)?;

    if verbose {
        eprintln!("subordinate UIDs for {username}: start={subuid_start}, count={subuid_count}");
        eprintln!("subordinate GIDs for {username}: start={subgid_start}, count={subgid_count}");
    }

    check_subid_helpers()?;

    // Create a pipe for child→parent error reporting.
    let mut err_pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(err_pipe_fds.as_mut_ptr()) } != 0 {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(std::io::Error::last_os_error())
            .context("failed to create error-reporting pipe");
    }

    // Create sync pipes for parent↔child coordination.
    // ready_pipe: child writes "ready" byte after unshare, parent reads it.
    // go_pipe: parent writes "go" byte after UID mapping, child reads it.
    let mut ready_pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(ready_pipe_fds.as_mut_ptr()) } != 0 {
        unsafe {
            libc::close(err_pipe_fds[0]);
            libc::close(err_pipe_fds[1]);
        }
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(std::io::Error::last_os_error())
            .context("failed to create ready pipe");
    }

    let mut go_pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(go_pipe_fds.as_mut_ptr()) } != 0 {
        unsafe {
            libc::close(err_pipe_fds[0]);
            libc::close(err_pipe_fds[1]);
            libc::close(ready_pipe_fds[0]);
            libc::close(ready_pipe_fds[1]);
        }
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(std::io::Error::last_os_error())
            .context("failed to create go pipe");
    }

    if verbose {
        eprintln!("forking child process (uid={real_uid}, gid={real_gid})");
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(err_pipe_fds[0]);
            libc::close(err_pipe_fds[1]);
            libc::close(ready_pipe_fds[0]);
            libc::close(ready_pipe_fds[1]);
            libc::close(go_pipe_fds[0]);
            libc::close(go_pipe_fds[1]);
        }
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(std::io::Error::last_os_error()).context("fork failed");
    }

    if pid == 0 {
        // Child process: close parent ends of all pipes.
        unsafe {
            libc::close(err_pipe_fds[0]);
            libc::close(ready_pipe_fds[0]);
            libc::close(go_pipe_fds[1]);
        }

        let mut err_pipe = unsafe { std::fs::File::from_raw_fd(err_pipe_fds[1]) };
        let ready_write = unsafe { std::fs::File::from_raw_fd(ready_pipe_fds[1]) };
        let go_read = unsafe { std::fs::File::from_raw_fd(go_pipe_fds[0]) };

        match child_import_tar(
            &merged_dir, &lower_dir, &upper_dir, &work_dir,
            ready_write, go_read,
            tar_path, verbose,
        ) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                let msg = format!("{e:#}");
                let _ = err_pipe.write_all(msg.as_bytes());
                drop(err_pipe);
                std::process::exit(1);
            }
        }
    }

    // Parent process: close child ends of all pipes.
    unsafe {
        libc::close(err_pipe_fds[1]);
        libc::close(ready_pipe_fds[1]);
        libc::close(go_pipe_fds[0]);
    }

    // Wait for child to signal "ready" (after unshare).
    {
        let mut ready_read = unsafe { std::fs::File::from_raw_fd(ready_pipe_fds[0]) };
        let mut go_write = unsafe { std::fs::File::from_raw_fd(go_pipe_fds[1]) };
        let mut ready_buf = [0u8; 1];
        ready_read
            .read_exact(&mut ready_buf)
            .context("failed to read sync signal from child; child may have exited")?;

        if verbose {
            eprintln!("child signaled ready; setting up UID/GID mapping");
        }

        // Call newuidmap: 0 <real_uid> 1 1 <subuid_start> <subuid_count>
        let uid_status = std::process::Command::new("newuidmap")
            .arg(pid.to_string())
            .arg("0").arg(real_uid.to_string()).arg("1")
            .arg("1").arg(subuid_start.to_string()).arg(subuid_count.to_string())
            .status()
            .context("failed to execute newuidmap")?;

        if verbose {
            eprintln!("newuidmap exited with {uid_status}");
        }

        if !uid_status.success() {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let mut status: i32 = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            unsafe { libc::close(err_pipe_fds[0]) };
            let _ = make_removable(&staging_dir);
            let _ = fs::remove_dir_all(&staging_dir);
            bail!("newuidmap failed with {uid_status}");
        }

        // Call newgidmap: 0 <real_gid> 1 1 <subgid_start> <subgid_count>
        let gid_status = std::process::Command::new("newgidmap")
            .arg(pid.to_string())
            .arg("0").arg(real_gid.to_string()).arg("1")
            .arg("1").arg(subgid_start.to_string()).arg(subgid_count.to_string())
            .status()
            .context("failed to execute newgidmap")?;

        if verbose {
            eprintln!("newgidmap exited with {gid_status}");
        }

        if !gid_status.success() {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let mut status: i32 = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            unsafe { libc::close(err_pipe_fds[0]) };
            let _ = make_removable(&staging_dir);
            let _ = fs::remove_dir_all(&staging_dir);
            bail!("newgidmap failed with {gid_status}");
        }

        // Signal child to continue ("go").
        go_write
            .write_all(&[1u8])
            .context("failed to send go signal to child")?;
    }

    if verbose {
        eprintln!("waiting for child process (pid={pid})");
    }

    let mut status: i32 = 0;
    loop {
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            let _ = make_removable(&staging_dir);
            let _ = fs::remove_dir_all(&staging_dir);
            unsafe { libc::close(err_pipe_fds[0]) };
            return Err(err).context("waitpid failed");
        }
        break;
    }

    let success = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;

    if success {
        unsafe { libc::close(err_pipe_fds[0]) };

        if verbose {
            eprintln!("child process completed successfully");
        }

        // Move the overlay upper dir to the final rootfs location.
        fs::rename(&upper_dir, &final_dir).with_context(|| {
            format!(
                "failed to rename {} to {}",
                upper_dir.display(),
                final_dir.display()
            )
        })?;

        if verbose {
            eprintln!("moved upper dir to {}", final_dir.display());
        }

        // Write distro metadata sidecar.
        let distro = detect_distro(&final_dir);
        let mut meta = State::new();
        meta.set("DISTRO", &distro);
        let meta_path = rootfs_dir.join(format!(".{name}.meta"));
        meta.write_to(&meta_path)?;

        if verbose {
            if distro.is_empty() {
                eprintln!("wrote metadata sidecar (no distro detected)");
            } else {
                eprintln!("wrote metadata sidecar (distro: {distro})");
            }
        }

        // Clean up remaining staging dirs.
        let _ = fs::remove_dir_all(&staging_dir);

        if verbose {
            eprintln!("cleaned up staging directory");
        }

        Ok(())
    } else {
        // Read error message from the child.
        let mut err_msg = String::new();
        let mut err_pipe =
            unsafe { std::fs::File::from_raw_fd(err_pipe_fds[0]) };
        let _ = err_pipe.read_to_string(&mut err_msg);

        let _ = make_removable(&staging_dir);
        let _ = fs::remove_dir_all(&staging_dir);

        if err_msg.is_empty() {
            let exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            };
            bail!("tar import failed (child exited with status {exit_code})");
        } else {
            bail!("tar import failed: {err_msg}");
        }
    }
}

/// Child process logic: enter a user namespace, mount overlayfs, extract tar.
///
/// Enters a new user+mount namespace, signals the parent via `ready_write` so
/// the parent can set up UID/GID mappings with newuidmap/newgidmap, then waits
/// for the parent to signal via `go_read` before mounting overlayfs and
/// extracting the tar stream.
///
/// When `tar_path` is `None`, reads from stdin. When `Some`, reads from the file.
fn child_import_tar(
    merged: &Path,
    lower: &Path,
    upper: &Path,
    work: &Path,
    mut ready_write: std::fs::File,
    mut go_read: std::fs::File,
    tar_path: Option<&Path>,
    verbose: bool,
) -> Result<()> {
    if verbose {
        eprintln!("entering user and mount namespaces");
    }

    // Enter new user + mount namespaces.
    let ret = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).context(
            "unshare(CLONE_NEWUSER|CLONE_NEWNS) failed; \
             this may be due to system restrictions — ensure the following sysctl settings:\n  \
             kernel.unprivileged_userns_clone=1\n  \
             kernel.apparmor_restrict_unprivileged_userns=0"
        );
    }

    // Signal parent that we've entered the namespace ("ready").
    ready_write
        .write_all(&[1u8])
        .context("failed to send ready signal to parent")?;
    drop(ready_write);

    // Wait for parent to set up UID/GID mappings ("go").
    let mut go_buf = [0u8; 1];
    go_read
        .read_exact(&mut go_buf)
        .context("failed to read go signal from parent")?;
    drop(go_read);

    if verbose {
        eprintln!("UID/GID mapping configured by parent; continuing");
    }

    // Mount overlayfs.
    let overlay_opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display(),
    );
    let c_merged = CString::new(merged.as_os_str().as_bytes())
        .context("merged path contains null byte")?;
    let c_fstype = CString::new("overlay").unwrap();
    let c_source = CString::new("overlay").unwrap();
    let c_opts = CString::new(overlay_opts.as_bytes())
        .context("overlay options contain null byte")?;

    let ret = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_merged.as_ptr(),
            c_fstype.as_ptr(),
            0,
            c_opts.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to mount overlayfs");
    }

    if verbose {
        eprintln!("mounted overlayfs on {}", merged.display());
    }

    // Extract tar into the merged directory.
    let tar_input = match tar_path {
        Some(p) => p.as_os_str().to_os_string(),
        None => std::ffi::OsString::from("-"),
    };

    if verbose {
        match tar_path {
            Some(p) => eprintln!("extracting {} into overlay...", p.display()),
            None => eprintln!("extracting tar from stdin into overlay..."),
        }
    }

    let tar_output = std::process::Command::new("tar")
        .arg("xpf")
        .arg(&tar_input)
        .arg("-C")
        .arg(merged)
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::piped())
        .output()
        .context("failed to execute tar")?;

    if verbose {
        eprintln!("tar exited with {}", tar_output.status);
    }

    // Classify tar stderr for error handling.
    let stderr_text = String::from_utf8_lossy(&tar_output.stderr);
    if verbose && !stderr_text.is_empty() {
        eprintln!("tar stderr:\n{stderr_text}");
    }

    let tar_ok = if tar_output.status.success() {
        true
    } else {
        // Check if all stderr lines are expected/harmless.
        let has_real_errors = stderr_text.lines().any(|line| {
            let line = line.trim();
            if line.is_empty() {
                return false;
            }
            // Informational lines from tar.
            if line.contains("Removing leading") || line.contains("Exiting with failure status") {
                return false;
            }
            // Expected in user namespaces: mknod failures (nspawn populates /dev).
            if line.contains("Cannot mknod") {
                return false;
            }
            true
        });
        if has_real_errors {
            false
        } else {
            if verbose {
                eprintln!("tar exited non-zero but all errors are expected in user namespace (mknod); continuing");
            }
            true
        }
    };

    if verbose {
        eprintln!("unmounting overlayfs");
    }

    // Unmount overlayfs to flush metadata to upper dir.
    let ret = unsafe { libc::umount(c_merged.as_ptr()) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if !tar_ok {
            bail!("tar extraction failed with {}: {}", tar_output.status, stderr_text.trim());
        }
        return Err(err).context("failed to unmount overlayfs");
    }

    if !tar_ok {
        bail!("tar extraction failed with {}: {}", tar_output.status, stderr_text.trim());
    }

    Ok(())
}

/// Remove a leftover staging directory from a previous failed import.
///
/// When `force` is true, attempts to fix permissions and remove the directory.
/// When `force` is false and the directory exists, returns an error telling
/// the user to retry with `-f`.
fn cleanup_staging(staging_dir: &Path, force: bool, verbose: bool) -> Result<()> {
    if !staging_dir.exists() {
        return Ok(());
    }
    if !force {
        bail!(
            "staging directory already exists: {}\n\
             a previous import may have failed; re-run with -f to remove it and try again",
            staging_dir.display()
        );
    }
    if verbose {
        eprintln!("removing leftover staging directory: {}", staging_dir.display());
    }
    let _ = make_removable(staging_dir);
    fs::remove_dir_all(staging_dir)
        .with_context(|| format!("failed to remove staging directory {}", staging_dir.display()))?;
    Ok(())
}

/// Check that the `tar` binary is available on PATH.
fn check_tar_available() -> Result<()> {
    match std::process::Command::new("tar").arg("--version").output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(_) => bail!("tar binary found but returned an error; is it working?"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("tar binary not found; please install tar (e.g. apt install tar)")
        }
        Err(e) => Err(e).context("failed to check for tar binary"),
    }
}

fn do_import(source: &Path, staging: &Path, verbose: bool, privileged: bool) -> Result<()> {
    // Create the staging directory and copy the root directory's metadata.
    fs::create_dir(staging)
        .with_context(|| format!("failed to create staging dir {}", staging.display()))?;
    copy_metadata(source, staging, privileged)
        .with_context(|| format!("failed to copy metadata for {}", source.display()))?;
    copy_xattrs(source, staging, privileged)?;

    if verbose {
        eprintln!("copying {} -> {}", source.display(), staging.display());
    }

    copy_tree(source, staging, verbose, privileged)
}

fn copy_tree(src_dir: &Path, dst_dir: &Path, verbose: bool, privileged: bool) -> Result<()> {
    let entries = fs::read_dir(src_dir)
        .with_context(|| format!("failed to read directory {}", src_dir.display()))?;

    for entry in entries {
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", src_dir.display()))?;
        let src_path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst_dir.join(&file_name);

        copy_entry(&src_path, &dst_path, verbose, privileged)
            .with_context(|| format!("failed to copy {}", src_path.display()))?;
    }

    Ok(())
}

fn copy_entry(src: &Path, dst: &Path, verbose: bool, privileged: bool) -> Result<()> {
    let stat = lstat_entry(src)?;
    let mode = stat.st_mode & libc::S_IFMT;

    match mode {
        libc::S_IFDIR => {
            fs::create_dir(dst)
                .with_context(|| format!("failed to create directory {}", dst.display()))?;
            copy_metadata_from_stat(dst, &stat, privileged)?;
            copy_xattrs(src, dst, privileged)?;
            copy_tree(src, dst, verbose, privileged)?;
        }
        libc::S_IFREG => {
            fs::copy(src, dst)
                .with_context(|| format!("failed to copy file {}", src.display()))?;
            copy_metadata_from_stat(dst, &stat, privileged)?;
            copy_xattrs(src, dst, privileged)?;
        }
        libc::S_IFLNK => {
            let target = fs::read_link(src)
                .with_context(|| format!("failed to read symlink {}", src.display()))?;
            unix_fs::symlink(&target, dst)
                .with_context(|| format!("failed to create symlink {}", dst.display()))?;
            if privileged {
                lchown(dst, stat.st_uid, stat.st_gid)?;
            }
            // Timestamps for symlinks.
            let c_path = path_to_cstring(dst)?;
            let times = [
                libc::timespec {
                    tv_sec: stat.st_atime,
                    tv_nsec: stat.st_atime_nsec,
                },
                libc::timespec {
                    tv_sec: stat.st_mtime,
                    tv_nsec: stat.st_mtime_nsec,
                },
            ];
            let ret = unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    c_path.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                // ENOTSUP on some filesystems for symlink timestamps — not fatal.
                if err.raw_os_error() != Some(libc::ENOTSUP) {
                    return Err(err)
                        .with_context(|| format!("utimensat failed for {}", dst.display()));
                }
            }
            copy_xattrs(src, dst, privileged)?;
        }
        libc::S_IFBLK | libc::S_IFCHR => {
            if !privileged {
                eprintln!(
                    "warning: skipping device node {} (requires root)",
                    src.display()
                );
                return Ok(());
            }
            let c_path = path_to_cstring(dst)?;
            let ret = unsafe { libc::mknod(c_path.as_ptr(), stat.st_mode, stat.st_rdev) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("mknod failed for {}", dst.display()));
            }
            copy_metadata_from_stat(dst, &stat, privileged)?;
            copy_xattrs(src, dst, privileged)?;
        }
        libc::S_IFIFO => {
            let c_path = path_to_cstring(dst)?;
            let ret = unsafe { libc::mkfifo(c_path.as_ptr(), stat.st_mode & 0o7777) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("mkfifo failed for {}", dst.display()));
            }
            copy_metadata_from_stat(dst, &stat, privileged)?;
            copy_xattrs(src, dst, privileged)?;
        }
        libc::S_IFSOCK => {
            let c_path = path_to_cstring(dst)?;
            let ret =
                unsafe { libc::mknod(c_path.as_ptr(), libc::S_IFSOCK | (stat.st_mode & 0o7777), 0) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("mknod (socket) failed for {}", dst.display()));
            }
            copy_metadata_from_stat(dst, &stat, privileged)?;
            copy_xattrs(src, dst, privileged)?;
        }
        _ => {
            eprintln!(
                "warning: skipping unknown file type {:o} for {}",
                mode,
                src.display()
            );
        }
    }

    Ok(())
}

fn copy_metadata_from_stat(dst: &Path, stat: &libc::stat, privileged: bool) -> Result<()> {
    let c_path = path_to_cstring(dst)?;

    // Ownership — skip when unprivileged (would EPERM for foreign UIDs).
    if privileged {
        let ret = unsafe { libc::lchown(c_path.as_ptr(), stat.st_uid, stat.st_gid) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("lchown failed for {}", dst.display()));
        }
    }

    // Permission bits (skip for symlinks — chmod doesn't apply to them).
    // When unprivileged, SUID/SGID bits are silently cleared by the kernel.
    let file_type = stat.st_mode & libc::S_IFMT;
    if file_type != libc::S_IFLNK {
        let ret = unsafe { libc::chmod(c_path.as_ptr(), stat.st_mode & 0o7777) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("chmod failed for {}", dst.display()));
        }
    }

    // Timestamps with nanosecond precision.
    let times = [
        libc::timespec {
            tv_sec: stat.st_atime,
            tv_nsec: stat.st_atime_nsec,
        },
        libc::timespec {
            tv_sec: stat.st_mtime,
            tv_nsec: stat.st_mtime_nsec,
        },
    ];
    let ret = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOTSUP) {
            return Err(err).with_context(|| format!("utimensat failed for {}", dst.display()));
        }
    }

    Ok(())
}

fn copy_metadata(src: &Path, dst: &Path, privileged: bool) -> Result<()> {
    let stat = lstat_entry(src)?;
    copy_metadata_from_stat(dst, &stat, privileged)
}

fn copy_xattrs(src: &Path, dst: &Path, privileged: bool) -> Result<()> {
    let c_src = path_to_cstring(src)?;
    let c_dst = path_to_cstring(dst)?;

    // Get the size of the xattr name list.
    let size = unsafe { libc::llistxattr(c_src.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTSUP) || err.raw_os_error() == Some(libc::ENODATA)
        {
            return Ok(());
        }
        return Err(err).with_context(|| format!("llistxattr failed for {}", src.display()));
    }
    if size == 0 {
        return Ok(());
    }

    let mut names_buf = vec![0u8; size as usize];
    let size = unsafe {
        libc::llistxattr(
            c_src.as_ptr(),
            names_buf.as_mut_ptr() as *mut libc::c_char,
            names_buf.len(),
        )
    };
    if size < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("llistxattr failed for {}", src.display()));
    }

    // Parse null-terminated name list.
    let names_buf = &names_buf[..size as usize];
    for name_bytes in names_buf.split(|&b| b == 0) {
        if name_bytes.is_empty() {
            continue;
        }

        // Skip security.selinux.
        if name_bytes.starts_with(b"security.selinux") {
            continue;
        }

        // Skip trusted.* xattrs when unprivileged — requires CAP_SYS_ADMIN.
        if !privileged && name_bytes.starts_with(b"trusted.") {
            continue;
        }

        let c_name = CString::new(name_bytes)
            .with_context(|| "xattr name contains interior null byte")?;

        // Get xattr value size.
        let val_size =
            unsafe { libc::lgetxattr(c_src.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if val_size < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENODATA) {
                continue;
            }
            return Err(err).with_context(|| {
                format!(
                    "lgetxattr failed for {} attr {}",
                    src.display(),
                    c_name.to_string_lossy()
                )
            });
        }

        let mut val_buf = vec![0u8; val_size as usize];
        let val_size = unsafe {
            libc::lgetxattr(
                c_src.as_ptr(),
                c_name.as_ptr(),
                val_buf.as_mut_ptr() as *mut libc::c_void,
                val_buf.len(),
            )
        };
        if val_size < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "lgetxattr failed for {} attr {}",
                    src.display(),
                    c_name.to_string_lossy()
                )
            });
        }

        let ret = unsafe {
            libc::lsetxattr(
                c_dst.as_ptr(),
                c_name.as_ptr(),
                val_buf.as_ptr() as *const libc::c_void,
                val_size as usize,
                0,
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOTSUP) {
                return Ok(());
            }
            return Err(err).with_context(|| {
                format!(
                    "lsetxattr failed for {} attr {}",
                    dst.display(),
                    c_name.to_string_lossy()
                )
            });
        }
    }

    Ok(())
}

/// Remove an imported root filesystem.
///
/// Validates the name, checks that no container references it, then removes
/// the rootfs directory and its `.meta` sidecar.
pub fn remove(datadir: &Path, name: &str, verbose: bool) -> Result<()> {
    validate_name(name)?;

    let rootfs_path = datadir.join("rootfs").join(name);
    if !rootfs_path.exists() {
        bail!("rootfs not found: {name}");
    }

    // Check that no container is using this rootfs.
    let state_dir = datadir.join("state");
    if state_dir.is_dir() {
        for entry in fs::read_dir(&state_dir)
            .with_context(|| format!("failed to read {}", state_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if let Ok(state) = State::read_from(&path) {
                if state.get("ROOTFS") == Some(name) {
                    let container = match state.get("NAME") {
                        Some(n) => n.to_string(),
                        None => entry
                            .file_name()
                            .to_str()
                            .unwrap_or("unknown")
                            .to_string(),
                    };
                    bail!("rootfs '{name}' is in use by container '{container}'");
                }
            }
        }
    }

    let privileged = unsafe { libc::geteuid() == 0 };
    if privileged {
        make_removable(&rootfs_path)?;
        fs::remove_dir_all(&rootfs_path)
            .with_context(|| format!("failed to remove {}", rootfs_path.display()))?;
    } else {
        remove_in_userns(&rootfs_path, verbose)?;
    }

    let meta_path = datadir.join("rootfs").join(format!(".{name}.meta"));
    let _ = fs::remove_file(meta_path);

    if verbose {
        eprintln!("removed rootfs '{name}'");
    }

    Ok(())
}

/// Remove a directory tree from inside a user namespace where subordinate UIDs
/// are mapped, giving us CAP_DAC_OVERRIDE to delete files owned by those UIDs.
fn remove_in_userns(path: &Path, _verbose: bool) -> Result<()> {
    let real_uid = unsafe { libc::getuid() };
    let real_gid = unsafe { libc::getgid() };

    let username = {
        let pw = unsafe { libc::getpwuid(real_uid) };
        if pw.is_null() {
            bail!("failed to look up username for uid {real_uid}");
        }
        unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }
            .to_str()
            .context("username is not valid UTF-8")?
            .to_string()
    };

    let (subuid_start, subuid_count) = parse_subid_file(Path::new("/etc/subuid"), &username)?;
    let (subgid_start, subgid_count) = parse_subid_file(Path::new("/etc/subgid"), &username)?;
    check_subid_helpers()?;

    let mut err_pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(err_pipe_fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create error pipe");
    }

    let mut ready_pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(ready_pipe_fds.as_mut_ptr()) } != 0 {
        unsafe { libc::close(err_pipe_fds[0]); libc::close(err_pipe_fds[1]); }
        return Err(std::io::Error::last_os_error()).context("failed to create ready pipe");
    }

    let mut go_pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(go_pipe_fds.as_mut_ptr()) } != 0 {
        unsafe {
            libc::close(err_pipe_fds[0]); libc::close(err_pipe_fds[1]);
            libc::close(ready_pipe_fds[0]); libc::close(ready_pipe_fds[1]);
        }
        return Err(std::io::Error::last_os_error()).context("failed to create go pipe");
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(err_pipe_fds[0]); libc::close(err_pipe_fds[1]);
            libc::close(ready_pipe_fds[0]); libc::close(ready_pipe_fds[1]);
            libc::close(go_pipe_fds[0]); libc::close(go_pipe_fds[1]);
        }
        return Err(std::io::Error::last_os_error()).context("fork failed");
    }

    if pid == 0 {
        // Child: close parent ends.
        unsafe {
            libc::close(err_pipe_fds[0]);
            libc::close(ready_pipe_fds[0]);
            libc::close(go_pipe_fds[1]);
        }

        let mut err_pipe = unsafe { std::fs::File::from_raw_fd(err_pipe_fds[1]) };
        let mut ready_write = unsafe { std::fs::File::from_raw_fd(ready_pipe_fds[1]) };
        let mut go_read = unsafe { std::fs::File::from_raw_fd(go_pipe_fds[0]) };

        let result = (|| -> Result<()> {
            // Enter new user namespace.
            let ret = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error()).context("unshare(CLONE_NEWUSER) failed");
            }

            // Signal parent that we're ready for UID mapping.
            ready_write.write_all(&[1u8]).context("failed to send ready signal")?;
            drop(ready_write);

            // Wait for parent to set up mappings.
            let mut buf = [0u8; 1];
            go_read.read_exact(&mut buf).context("failed to read go signal")?;
            drop(go_read);

            // Now we are root inside the namespace — remove the tree.
            make_removable(path)?;
            fs::remove_dir_all(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
            Ok(())
        })();

        match result {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                let msg = format!("{e:#}");
                let _ = err_pipe.write_all(msg.as_bytes());
                drop(err_pipe);
                std::process::exit(1);
            }
        }
    }

    // Parent: close child ends.
    unsafe {
        libc::close(err_pipe_fds[1]);
        libc::close(ready_pipe_fds[1]);
        libc::close(go_pipe_fds[0]);
    }

    {
        let mut ready_read = unsafe { std::fs::File::from_raw_fd(ready_pipe_fds[0]) };
        let mut go_write = unsafe { std::fs::File::from_raw_fd(go_pipe_fds[1]) };
        let mut ready_buf = [0u8; 1];
        ready_read
            .read_exact(&mut ready_buf)
            .context("failed to read ready signal from child")?;

        let uid_status = std::process::Command::new("newuidmap")
            .arg(pid.to_string())
            .arg("0").arg(real_uid.to_string()).arg("1")
            .arg("1").arg(subuid_start.to_string()).arg(subuid_count.to_string())
            .status()
            .context("failed to execute newuidmap")?;
        if !uid_status.success() {
            unsafe { libc::kill(pid, libc::SIGKILL); }
            let mut status = 0i32;
            unsafe { libc::waitpid(pid, &mut status, 0); libc::close(err_pipe_fds[0]); }
            bail!("newuidmap failed with {uid_status}");
        }

        let gid_status = std::process::Command::new("newgidmap")
            .arg(pid.to_string())
            .arg("0").arg(real_gid.to_string()).arg("1")
            .arg("1").arg(subgid_start.to_string()).arg(subgid_count.to_string())
            .status()
            .context("failed to execute newgidmap")?;
        if !gid_status.success() {
            unsafe { libc::kill(pid, libc::SIGKILL); }
            let mut status = 0i32;
            unsafe { libc::waitpid(pid, &mut status, 0); libc::close(err_pipe_fds[0]); }
            bail!("newgidmap failed with {gid_status}");
        }

        go_write.write_all(&[1u8]).context("failed to send go signal")?;
    }

    let mut status = 0i32;
    loop {
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            unsafe { libc::close(err_pipe_fds[0]); }
            return Err(err).context("waitpid failed");
        }
        break;
    }

    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        unsafe { libc::close(err_pipe_fds[0]); }
        Ok(())
    } else {
        let mut err_msg = String::new();
        let mut err_pipe = unsafe { std::fs::File::from_raw_fd(err_pipe_fds[0]) };
        let _ = err_pipe.read_to_string(&mut err_msg);
        if err_msg.is_empty() {
            bail!("child process failed (status={status})");
        } else {
            bail!("{err_msg}");
        }
    }
}

/// Recursively restore directory permissions so `remove_dir_all` can succeed.
fn make_removable(path: &Path) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o700 != 0o700 {
            fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))?;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let _ = make_removable(&entry.path());
            }
        }
    }
    Ok(())
}

fn lstat_entry(path: &Path) -> Result<libc::stat> {
    let c_path = path_to_cstring(path)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::lstat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("lstat failed for {}", path.display()));
    }
    Ok(stat)
}

fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains null byte: {}", path.display()))
}

fn lchown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let c_path = path_to_cstring(path)?;
    let ret = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("lchown failed for {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempDataDir {
        dir: std::path::PathBuf,
    }

    impl TempDataDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-rootfs-{}-{:?}",
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

    struct TempSourceDir {
        dir: std::path::PathBuf,
    }

    impl TempSourceDir {
        fn new(suffix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sdme-test-rootfs-src-{}-{:?}-{suffix}",
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

    impl Drop for TempSourceDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn test_import_basic_directory() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("basic");

        // Create source structure.
        fs::write(src.path().join("hello.txt"), "hello world\n").unwrap();
        fs::create_dir(src.path().join("subdir")).unwrap();
        fs::write(src.path().join("subdir/nested.txt"), "nested\n").unwrap();

        import(tmp.path(), src.path(), "test", false, true, false).unwrap();

        let rootfs = tmp.path().join("rootfs/test");
        assert!(rootfs.is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "hello world\n"
        );
        assert!(rootfs.join("subdir").is_dir());
        assert_eq!(
            fs::read_to_string(rootfs.join("subdir/nested.txt")).unwrap(),
            "nested\n"
        );
    }

    #[test]
    fn test_import_preserves_permissions() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("perms");

        let file_path = src.path().join("script.sh");
        fs::write(&file_path, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o755)).unwrap();

        let ro_path = src.path().join("readonly.txt");
        fs::write(&ro_path, "data\n").unwrap();
        fs::set_permissions(&ro_path, fs::Permissions::from_mode(0o644)).unwrap();

        let suid_path = src.path().join("suid");
        fs::write(&suid_path, "suid\n").unwrap();
        fs::set_permissions(&suid_path, fs::Permissions::from_mode(0o4755)).unwrap();

        import(tmp.path(), src.path(), "perms", false, true, false).unwrap();

        let rootfs = tmp.path().join("rootfs/perms");
        let meta = fs::metadata(rootfs.join("script.sh")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o755);

        let meta = fs::metadata(rootfs.join("readonly.txt")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o644);

        let meta = fs::metadata(rootfs.join("suid")).unwrap();
        if crate::is_privileged() {
            assert_eq!(meta.permissions().mode() & 0o7777, 0o4755);
        } else {
            // Kernel silently clears SUID when not owner-root.
            assert_eq!(meta.permissions().mode() & 0o0777, 0o755);
        }
    }

    #[test]
    fn test_import_preserves_symlinks() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("symlinks");

        fs::write(src.path().join("target.txt"), "target\n").unwrap();
        unix_fs::symlink("target.txt", src.path().join("link.txt")).unwrap();
        // Dangling symlink.
        unix_fs::symlink("/nonexistent", src.path().join("dangling")).unwrap();

        import(tmp.path(), src.path(), "sym", false, true, false).unwrap();

        let rootfs = tmp.path().join("rootfs/sym");
        let link_target = fs::read_link(rootfs.join("link.txt")).unwrap();
        assert_eq!(link_target.to_str().unwrap(), "target.txt");

        let dangling_target = fs::read_link(rootfs.join("dangling")).unwrap();
        assert_eq!(dangling_target.to_str().unwrap(), "/nonexistent");
    }

    #[test]
    fn test_import_duplicate_name() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("dup");

        import(tmp.path(), src.path(), "dup", false, true, false).unwrap();
        let err = import(tmp.path(), src.path(), "dup", false, true, false).unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_import_invalid_name() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("invalid");

        let err = import(tmp.path(), src.path(), "INVALID", false, true, false).unwrap_err();
        assert!(
            err.to_string().contains("lowercase"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_import_source_not_directory() {
        let tmp = TempDataDir::new();
        let file_path = std::env::temp_dir().join(format!(
            "sdme-test-rootfs-notdir-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&file_path, "not a dir").unwrap();

        let err = import(tmp.path(), &file_path, "test", false, true, false).unwrap_err();
        assert!(
            err.to_string().contains("not a directory"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_import_source_not_found() {
        let tmp = TempDataDir::new();
        let missing = Path::new("/tmp/sdme-test-definitely-nonexistent");

        let err = import(tmp.path(), missing, "test", false, true, false).unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_import_cleanup_on_failure() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("cleanup");

        // Create a subdirectory that can't be read.
        let unreadable = src.path().join("secret");
        fs::create_dir(&unreadable).unwrap();
        fs::write(unreadable.join("file.txt"), "data").unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

        let result = import(tmp.path(), src.path(), "fail", false, true, false);
        assert!(result.is_err());

        // Staging dir should be cleaned up.
        let staging = tmp.path().join("rootfs/.fail.importing");
        assert!(!staging.exists(), "staging dir was not cleaned up");

        // Final dir should not exist.
        let final_dir = tmp.path().join("rootfs/fail");
        assert!(!final_dir.exists(), "final dir should not exist");

        // Restore permissions so TempSourceDir can clean up.
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn test_import_preserves_empty_directories() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("emptydir");

        fs::create_dir(src.path().join("empty")).unwrap();
        fs::create_dir(src.path().join("also-empty")).unwrap();

        import(tmp.path(), src.path(), "empty", false, true, false).unwrap();

        let rootfs = tmp.path().join("rootfs/empty");
        assert!(rootfs.join("empty").is_dir());
        assert!(rootfs.join("also-empty").is_dir());
        assert_eq!(fs::read_dir(rootfs.join("empty")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(rootfs.join("also-empty")).unwrap().count(), 0);
    }

    #[test]
    fn test_import_preserves_timestamps() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("timestamps");

        let file_path = src.path().join("file.txt");
        fs::write(&file_path, "data\n").unwrap();

        // Set a specific mtime.
        let times = [
            libc::timespec {
                tv_sec: 1000000000,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 1000000000,
                tv_nsec: 0,
            },
        ];
        let c_path = path_to_cstring(&file_path).unwrap();
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                times.as_ptr(),
                0,
            );
        }

        import(tmp.path(), src.path(), "ts", false, true, false).unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("rootfs/ts/file.txt")).unwrap();
        assert_eq!(dst_stat.st_mtime, 1000000000);
    }

    #[test]
    #[ignore] // Requires CAP_MKNOD (root).
    fn test_import_preserves_devices() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("devices");

        // Create a character device (null-like).
        let dev_path = src.path().join("null");
        let c_path = path_to_cstring(&dev_path).unwrap();
        let dev = libc::makedev(1, 3);
        let ret = unsafe { libc::mknod(c_path.as_ptr(), libc::S_IFCHR | 0o666, dev) };
        assert_eq!(ret, 0, "mknod failed (need root)");

        import(tmp.path(), src.path(), "dev", false, true, false).unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("rootfs/dev/null")).unwrap();
        assert_eq!(dst_stat.st_mode & libc::S_IFMT, libc::S_IFCHR);
        assert_eq!(dst_stat.st_rdev, dev);
    }

    #[test]
    fn test_import_stores_distro_metadata() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("distro");

        fs::create_dir_all(src.path().join("etc")).unwrap();
        fs::write(
            src.path().join("etc/os-release"),
            "PRETTY_NAME=\"Ubuntu 24.04.4 LTS\"\nNAME=\"Ubuntu\"\n",
        )
        .unwrap();

        import(tmp.path(), src.path(), "distro", false, true, false).unwrap();

        let meta_path = tmp.path().join("rootfs/.distro.meta");
        assert!(meta_path.exists(), ".meta sidecar should exist");
        let state = State::read_from(&meta_path).unwrap();
        assert_eq!(state.get("DISTRO").unwrap(), "Ubuntu 24.04.4 LTS");
    }

    #[test]
    fn test_import_no_os_release() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("no-os-release");

        fs::write(src.path().join("hello.txt"), "hi\n").unwrap();

        import(tmp.path(), src.path(), "noos", false, true, false).unwrap();

        let meta_path = tmp.path().join("rootfs/.noos.meta");
        assert!(meta_path.exists(), ".meta sidecar should exist");
        let state = State::read_from(&meta_path).unwrap();
        assert_eq!(state.get("DISTRO").unwrap(), "");
    }

    #[test]
    fn test_parse_os_release_quoted() {
        let tmp = TempSourceDir::new("quoted");

        fs::create_dir_all(tmp.path().join("etc")).unwrap();
        fs::write(
            tmp.path().join("etc/os-release"),
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nID=debian\n",
        )
        .unwrap();

        let map = parse_os_release(tmp.path());
        assert_eq!(
            map.get("PRETTY_NAME").unwrap(),
            "Debian GNU/Linux 12 (bookworm)"
        );
        assert_eq!(map.get("NAME").unwrap(), "Debian GNU/Linux");
        assert_eq!(map.get("ID").unwrap(), "debian");
    }

    #[test]
    fn test_parse_os_release_fallback_path() {
        let tmp = TempSourceDir::new("fallback");

        // No etc/os-release, but usr/lib/os-release exists.
        fs::create_dir_all(tmp.path().join("usr/lib")).unwrap();
        fs::write(
            tmp.path().join("usr/lib/os-release"),
            "PRETTY_NAME=\"Arch Linux\"\n",
        )
        .unwrap();

        let map = parse_os_release(tmp.path());
        assert_eq!(map.get("PRETTY_NAME").unwrap(), "Arch Linux");
    }

    #[test]
    fn test_list_empty() {
        let tmp = TempDataDir::new();
        let entries = list(tmp.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_list_entries() {
        let tmp = TempDataDir::new();

        // Import two rootfs with different distros.
        let src_a = TempSourceDir::new("list-a");
        fs::create_dir_all(src_a.path().join("etc")).unwrap();
        fs::write(
            src_a.path().join("etc/os-release"),
            "PRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
        )
        .unwrap();

        let src_b = TempSourceDir::new("list-b");
        fs::create_dir_all(src_b.path().join("etc")).unwrap();
        fs::write(
            src_b.path().join("etc/os-release"),
            "PRETTY_NAME=\"Debian 12\"\n",
        )
        .unwrap();

        import(tmp.path(), src_a.path(), "ubuntu", false, true, false).unwrap();
        import(tmp.path(), src_b.path(), "debian", false, true, false).unwrap();

        let entries = list(tmp.path()).unwrap();
        assert_eq!(entries.len(), 2);
        // Sorted by name.
        assert_eq!(entries[0].name, "debian");
        assert_eq!(entries[0].distro, "Debian 12");
        assert_eq!(entries[1].name, "ubuntu");
        assert_eq!(entries[1].distro, "Ubuntu 24.04 LTS");
    }

    #[test]
    fn test_list_skips_staging_dirs() {
        let tmp = TempDataDir::new();

        // Import a real rootfs.
        let src = TempSourceDir::new("staging");
        import(tmp.path(), src.path(), "real", false, true, false).unwrap();

        // Create a fake staging dir that should be skipped.
        fs::create_dir_all(tmp.path().join("rootfs/.fake.importing")).unwrap();

        let entries = list(tmp.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "real");
    }

    #[test]
    #[ignore] // Requires CAP_CHOWN (root).
    fn test_import_preserves_ownership() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("ownership");

        let file_path = src.path().join("owned.txt");
        fs::write(&file_path, "data\n").unwrap();
        let c_path = path_to_cstring(&file_path).unwrap();
        unsafe {
            libc::chown(c_path.as_ptr(), 1000, 1000);
        }

        import(tmp.path(), src.path(), "own", false, true, false).unwrap();

        let dst_stat = lstat_entry(&tmp.path().join("rootfs/own/owned.txt")).unwrap();
        assert_eq!(dst_stat.st_uid, 1000);
        assert_eq!(dst_stat.st_gid, 1000);
    }

    #[test]
    fn test_remove_basic() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("rm-basic");
        fs::write(src.path().join("file.txt"), "data\n").unwrap();

        import(tmp.path(), src.path(), "rmme", false, true, false).unwrap();
        assert!(tmp.path().join("rootfs/rmme").is_dir());
        assert!(tmp.path().join("rootfs/.rmme.meta").exists());

        remove(tmp.path(), "rmme", false).unwrap();
        assert!(!tmp.path().join("rootfs/rmme").exists());
        assert!(!tmp.path().join("rootfs/.rmme.meta").exists());
    }

    #[test]
    fn test_remove_not_found() {
        let tmp = TempDataDir::new();
        let err = remove(tmp.path(), "nonexistent", false).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_remove_in_use() {
        let tmp = TempDataDir::new();
        let src = TempSourceDir::new("rm-inuse");
        import(tmp.path(), src.path(), "inuse", false, true, false).unwrap();

        // Create a container state file that references this rootfs.
        let state_dir = tmp.path().join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let mut state = State::new();
        state.set("NAME", "mycontainer");
        state.set("ROOTFS", "inuse");
        state.write_to(&state_dir.join("mycontainer")).unwrap();

        let err = remove(tmp.path(), "inuse", false).unwrap_err();
        assert!(
            err.to_string().contains("in use"),
            "unexpected error: {err}"
        );
        // Rootfs should still exist.
        assert!(tmp.path().join("rootfs/inuse").is_dir());
    }

    #[test]
    fn test_remove_multiple() {
        let tmp = TempDataDir::new();
        let src_a = TempSourceDir::new("rm-multi-a");
        let src_b = TempSourceDir::new("rm-multi-b");

        import(tmp.path(), src_a.path(), "alpha", false, true, false).unwrap();
        import(tmp.path(), src_b.path(), "beta", false, true, false).unwrap();
        assert_eq!(list(tmp.path()).unwrap().len(), 2);

        remove(tmp.path(), "alpha", false).unwrap();
        remove(tmp.path(), "beta", false).unwrap();

        assert!(list(tmp.path()).unwrap().is_empty());
        assert!(!tmp.path().join("rootfs/alpha").exists());
        assert!(!tmp.path().join("rootfs/beta").exists());
    }

    #[test]
    fn test_parse_subid_file_valid() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-subid-valid-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&path, "testuser:100000:65536\n").unwrap();
        let (start, count) = parse_subid_file(&path, "testuser").unwrap();
        assert_eq!(start, 100000);
        assert_eq!(count, 65536);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_parse_subid_file_no_entry() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-subid-noentry-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&path, "otheruser:100000:65536\n").unwrap();
        let err = parse_subid_file(&path, "testuser").unwrap_err();
        assert!(
            err.to_string().contains("no subordinate IDs"),
            "unexpected error: {err}"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_parse_subid_file_multiple_entries() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-subid-multi-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(
            &path,
            "testuser:100000:65536\ntestuser:200000:65536\notheruser:300000:65536\n",
        )
        .unwrap();
        // First match wins.
        let (start, count) = parse_subid_file(&path, "testuser").unwrap();
        assert_eq!(start, 100000);
        assert_eq!(count, 65536);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_parse_subid_file_comments_and_blanks() {
        let path = std::env::temp_dir().join(format!(
            "sdme-test-subid-comments-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(
            &path,
            "# this is a comment\n\n  \notheruser:50000:1000\ntestuser:100000:65536\n",
        )
        .unwrap();
        let (start, count) = parse_subid_file(&path, "testuser").unwrap();
        assert_eq!(start, 100000);
        assert_eq!(count, 65536);
        let _ = fs::remove_file(&path);
    }
}
