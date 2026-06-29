pub mod detect;
pub mod manifest;

pub use detect::{compute_change_set, Baseline, ChangeSet};
pub use manifest::{ScanManifest, MANIFEST_FILE};
