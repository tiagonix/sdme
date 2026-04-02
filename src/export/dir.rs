//! Directory export: copy rootfs to a new directory.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::copy;

/// Export by copying the source directory tree to the destination.
pub(super) fn export_to_dir(src: &Path, dst: &Path, verbose: bool, force: bool) -> Result<()> {
    if dst.exists() {
        if force {
            fs::remove_dir_all(dst)
                .with_context(|| format!("failed to remove {}", dst.display()))?;
        } else {
            bail!("destination already exists: {}", dst.display());
        }
    }
    fs::create_dir_all(dst).with_context(|| format!("failed to create {}", dst.display()))?;
    copy::copy_metadata(src, dst)?;
    copy::copy_xattrs(src, dst)?;
    copy::copy_tree(src, dst, verbose)
        .with_context(|| format!("failed to copy {} to {}", src.display(), dst.display()))
}
