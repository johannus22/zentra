use crate::incremental::manifest::ScanManifest;
use crate::incremental::Baseline;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Full,
    Incremental,
}

#[derive(Debug, Clone)]
pub struct ModeDecision {
    pub mode: ScanMode,
    pub baseline: Baseline,
    pub reason: String,
}

pub struct ModeInputs<'a> {
    pub forced_full: bool,
    pub is_git_repo: bool,
    pub current_engine_version: &'a str,
    pub current_model_id: &'a str,
    pub prior: Option<&'a ScanManifest>,
}

fn full(reason: &str) -> ModeDecision {
    ModeDecision {
        mode: ScanMode::Full,
        baseline: Baseline::default(),
        reason: reason.to_string(),
    }
}

pub fn decide_mode(inputs: ModeInputs) -> ModeDecision {
    if inputs.forced_full {
        return full("full scan requested (--full)");
    }
    let Some(prior) = inputs.prior else {
        return full("no prior scan baseline — running full scan");
    };
    if prior.engine_version != inputs.current_engine_version {
        return full("engine version changed since last scan — running full scan");
    }
    if prior.model_id != inputs.current_model_id {
        return full("model/profile changed since last scan — running full scan");
    }

    if inputs.is_git_repo {
        match &prior.last_scan_commit {
            Some(commit) => ModeDecision {
                mode: ScanMode::Incremental,
                baseline: Baseline {
                    commit: Some(commit.clone()),
                    file_hashes: None,
                },
                reason: format!("incremental rescan (baseline {})", short(commit)),
            },
            None => full("no recorded baseline commit — running full scan"),
        }
    } else {
        match &prior.file_hashes {
            Some(hashes) => ModeDecision {
                mode: ScanMode::Incremental,
                baseline: Baseline {
                    commit: None,
                    file_hashes: Some(hashes.clone()),
                },
                reason: "incremental rescan (content-hash baseline)".to_string(),
            },
            None => full("no file-hash baseline (non-git repo) — running full scan"),
        }
    }
}

fn short(commit: &str) -> &str {
    // Char-safe truncation: a hand-edited manifest could hold a multibyte
    // string, and a byte slice would panic on a non-char-boundary.
    let end = commit
        .char_indices()
        .nth(8)
        .map(|(i, _)| i)
        .unwrap_or(commit.len());
    &commit[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incremental::manifest::ScanManifest;

    // F19: `short` byte-sliced &commit[..8]; a hand-edited manifest with a
    // multibyte commit string would panic on a non-char-boundary slice.
    #[test]
    fn short_handles_multibyte_commit_without_panicking() {
        assert_eq!(short("\u{20ac}\u{20ac}\u{20ac}\u{20ac}\u{20ac}").chars().count(), 5);
        assert!(short("abcdef1234567890").len() <= 8);
    }

    fn prior(commit: &str, version: &str, model: &str) -> ScanManifest {
        ScanManifest {
            last_scan_commit: Some(commit.into()),
            was_dirty: false,
            scanned_at: "t".into(),
            scanner_set: vec![],
            engine_version: version.into(),
            model_id: model.into(),
            mode: "full".into(),
            file_hashes: None,
        }
    }

    // Generic lifetime (no param of that lifetime) so callers may assign a
    // borrowed `prior` of any scope; the &'static str literals coerce freely.
    fn base_inputs<'a>() -> ModeInputs<'a> {
        ModeInputs {
            forced_full: false,
            is_git_repo: true,
            current_engine_version: "0.10.0",
            current_model_id: "claude",
            prior: None,
        }
    }

    #[test]
    fn no_prior_manifest_is_full() {
        let d = decide_mode(base_inputs());
        assert_eq!(d.mode, ScanMode::Full);
        assert!(d.reason.contains("no prior scan"));
    }

    #[test]
    fn matching_version_and_model_is_incremental() {
        let p = prior("base1", "0.10.0", "claude");
        let mut i = base_inputs();
        i.prior = Some(&p);
        let d = decide_mode(i);
        assert_eq!(d.mode, ScanMode::Incremental);
        assert_eq!(d.baseline.commit.as_deref(), Some("base1"));
    }

    #[test]
    fn forced_full_overrides() {
        let p = prior("base1", "0.10.0", "claude");
        let mut i = base_inputs();
        i.prior = Some(&p);
        i.forced_full = true;
        let d = decide_mode(i);
        assert_eq!(d.mode, ScanMode::Full);
        assert!(d.reason.contains("full") || d.reason.contains("--full"));
    }

    #[test]
    fn version_change_forces_full() {
        let p = prior("base1", "0.9.0", "claude");
        let mut i = base_inputs();
        i.prior = Some(&p);
        let d = decide_mode(i);
        assert_eq!(d.mode, ScanMode::Full);
        assert!(d.reason.contains("version"));
    }

    #[test]
    fn model_change_forces_full() {
        let p = prior("base1", "0.10.0", "gpt-4o");
        let mut i = base_inputs();
        i.prior = Some(&p);
        let d = decide_mode(i);
        assert_eq!(d.mode, ScanMode::Full);
        assert!(d.reason.contains("model"));
    }

    #[test]
    fn non_git_with_hashes_is_incremental() {
        let mut p = prior("ignored", "0.10.0", "claude");
        p.last_scan_commit = None;
        p.file_hashes = Some(Default::default());
        let mut i = base_inputs();
        i.is_git_repo = false;
        i.prior = Some(&p);
        let d = decide_mode(i);
        assert_eq!(d.mode, ScanMode::Incremental);
        assert!(d.baseline.commit.is_none());
        assert!(d.baseline.file_hashes.is_some());
    }

    #[test]
    fn non_git_without_hashes_is_full() {
        let p = prior("ignored", "0.10.0", "claude");
        let mut i = base_inputs();
        i.is_git_repo = false;
        i.prior = Some(&p);
        assert_eq!(decide_mode(i).mode, ScanMode::Full);
    }

    #[test]
    fn git_repo_without_commit_is_full() {
        let mut p = prior("base1", "0.10.0", "claude");
        p.last_scan_commit = None;
        let mut i = base_inputs(); // is_git_repo = true
        i.prior = Some(&p);
        let d = decide_mode(i);
        assert_eq!(d.mode, ScanMode::Full);
        assert!(d.reason.contains("baseline commit"));
    }
}
