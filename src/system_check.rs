use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::systemd;

fn parse_systemd_version(version: &str) -> Result<u32> {
    let digits: String = version.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        bail!("cannot parse systemd version: {version:?}");
    }
    digits
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("cannot parse systemd version: {e}"))
}

fn parse_kernel_version(release: &str) -> Result<(u32, u32, u32)> {
    let version_part = release.split('-').next().unwrap_or(release);
    let mut parts = version_part.split('.');
    let major: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("cannot parse kernel version: {release:?}"))?;
    let minor: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("cannot parse kernel version: {release:?}"))?;
    let patch: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    Ok((major, minor, patch))
}

/// Check that systemd is >= min_version.
/// Reads the "Version" property from org.freedesktop.systemd1.Manager via D-Bus.
pub fn check_systemd_version(privileged: bool, min_version: u32) -> Result<()> {
    let version_str = systemd::systemd_version(privileged)?;
    let version = parse_systemd_version(&version_str)?;
    if version < min_version {
        bail!(
            "systemd {min_version} or later is required (found {version})"
        );
    }
    Ok(())
}

/// Check that kernel is >= (major, minor).
/// Uses libc::uname() to read the release string.
/// Only called in rootless mode.
pub fn check_kernel_version(min_major: u32, min_minor: u32) -> Result<()> {
    let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::uname(&mut utsname) };
    if ret != 0 {
        bail!("uname() failed");
    }
    let release = unsafe {
        std::ffi::CStr::from_ptr(utsname.release.as_ptr())
    }
    .to_str()
    .map_err(|_| anyhow::anyhow!("kernel release is not valid UTF-8"))?;

    let (major, minor, _) = parse_kernel_version(release)?;
    if (major, minor) < (min_major, min_minor) {
        bail!(
            "kernel {min_major}.{min_minor} or later is required for rootless mode (found {release})"
        );
    }
    Ok(())
}

/// Find a program in PATH, returning its full path.
pub fn find_program(name: &str) -> Result<PathBuf> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("{name} not found in PATH")
}

/// Check that all required external programs are available.
///
/// `programs` is a slice of `(binary_name, package_hint)` pairs.
/// With `verbose`, prints the resolved path for each program.
pub fn check_dependencies(programs: &[(&str, &str)], verbose: bool) -> Result<()> {
    for (name, hint) in programs {
        match find_program(name) {
            Ok(path) => {
                if verbose {
                    eprintln!("found {name}: {}", path.display());
                }
            }
            Err(_) => {
                bail!("{name} not found; install it with: {hint}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_systemd_version_plain() {
        assert_eq!(parse_systemd_version("259").unwrap(), 259);
    }

    #[test]
    fn test_parse_systemd_version_with_suffix() {
        assert_eq!(parse_systemd_version("255-1ubuntu1").unwrap(), 255);
    }

    #[test]
    fn test_parse_systemd_version_empty() {
        assert!(parse_systemd_version("").is_err());
    }

    #[test]
    fn test_parse_kernel_version_standard() {
        assert_eq!(
            parse_kernel_version("6.19.0-6-generic").unwrap(),
            (6, 19, 0)
        );
    }

    #[test]
    fn test_parse_kernel_version_short() {
        assert_eq!(parse_kernel_version("5.11.0").unwrap(), (5, 11, 0));
    }

    #[test]
    fn test_parse_kernel_version_two_part() {
        assert_eq!(parse_kernel_version("5.11").unwrap(), (5, 11, 0));
    }

    #[test]
    fn test_check_kernel_version_current() {
        // Should pass on any modern system (kernel >= 5.11).
        check_kernel_version(5, 11).unwrap();
    }

    #[test]
    fn test_check_kernel_below_min() {
        // Verify comparison logic: parse "4.19.0" and confirm it would fail >= 5.11.
        let (major, minor, _) = parse_kernel_version("4.19.0").unwrap();
        assert!((major, minor) < (5, 11));
    }
}
