pub mod detect;
pub mod manifest;
pub mod mode;

pub use detect::{compute_change_set, Baseline, ChangeSet};
pub use manifest::{ScanManifest, MANIFEST_FILE};
pub use mode::{decide_mode, ModeDecision, ModeInputs, ScanMode};

/// New/Resolved/Carried summary for one incremental rescan. Computed by
/// reconciliation (Task 4); surfaced by the CLI/TUI (Tasks 7-8).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanDelta {
    pub new: usize,
    pub resolved: usize,
    pub carried: usize,
}
