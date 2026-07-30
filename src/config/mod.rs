pub mod custom_providers;
pub mod global;
pub mod keychain;
pub mod project;
pub mod secret_store;
pub mod validation;

use std::path::Path;

/// Write a file atomically: write a sibling temp file, fsync it, then rename it
/// over the target. A crash / Ctrl-C / disk-full mid-write can't leave a
/// truncated, unparseable config on disk (F15). Rename is atomic on the same
/// filesystem (and replaces the destination on Windows).
pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");
    let tmp = path.with_file_name(format!("{file_name}.tmp"));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

pub use custom_providers::CustomProvider;
pub use global::{
    cwe_link, global_zentra_dir, AuthMethod, GlobalConfig, ProviderProfile,
    DEFAULT_CWE_URL_TEMPLATE, DEFAULT_TEMPERATURE,
};
pub use project::ProjectConfig;
