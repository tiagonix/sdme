//! OCI container image support: layout parsing, registry pulling, app setup, and caching.

pub mod app;
pub mod cache;
pub mod layout;
pub mod registry;
pub mod rootfs;

/// Collect sorted keys from a HashMap and join them with a separator.
pub(crate) fn sorted_keys_joined(
    map: &std::collections::HashMap<String, serde_json::Value>,
    sep: &str,
) -> String {
    let mut keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
    keys.sort();
    keys.join(sep)
}

/// Collect sorted keys from a HashMap as a comma-separated string.
pub(crate) fn sorted_keys_csv(
    map: &std::collections::HashMap<String, serde_json::Value>,
) -> String {
    sorted_keys_joined(map, ", ")
}

/// Derive the OCI app name from an image reference string.
///
/// For registry images (e.g. `docker.io/nginx:latest`), returns the last
/// path component of the repository with underscores replaced by hyphens
/// (for systemd unit name compatibility).
/// For non-registry sources (tarballs, dirs), falls back to the rootfs name.
pub(crate) fn derive_app_name(source: &str, rootfs_name: &str) -> String {
    if let Some(img) = registry::ImageReference::parse(source) {
        let last = img.repository.rsplit('/').next().unwrap_or(&img.repository);
        last.replace('_', "-")
    } else {
        rootfs_name.to_string()
    }
}
