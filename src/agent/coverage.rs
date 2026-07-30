//! Scan coverage ledger.
//!
//! Zentra uses agentic exploration, so nothing guarantees an agent visits every
//! file. Three limits shape the path it takes: `list_files` returns directory
//! counts instead of names above 200 entries, `read_file` refuses files over
//! 100,000 bytes, and the ReAct loop stops after 30 iterations. In a large
//! repository an agent can spend the whole budget on navigation and never open a
//! source file. Before this ledger existed, that scan reported success.
//!
//! The ledger records what each scanner actually read, and the orchestrator
//! writes the result to `.zentra/coverage.md`. It reports; it never fails a run.

use std::collections::{BTreeMap, BTreeSet};

use crate::agent::ScannerType;
use crate::tools::fs_tools::ReadOutcome;

/// Never-read paths listed in the markdown before truncation. Matches the
/// truncate-with-a-note convention in `fs_tools::summarize_tree`.
const MAX_NEVER_READ_LISTED: usize = 20;

/// Per-scanner tallies. `files_read` counts distinct paths; the call counters
/// count calls, because one search can cover many files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScannerCoverage {
    pub scanner: String,
    pub files_read: usize,
    pub too_large: usize,
    pub failed: usize,
    pub listings: usize,
    pub searches: usize,
}

/// A point-in-time view of the ledger, with the candidate count folded in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoverageSummary {
    pub candidate_count: usize,
    /// Distinct files read by any scanner — a union, not a sum.
    pub distinct_read: usize,
    pub per_scanner: Vec<ScannerCoverage>,
}

impl CoverageSummary {
    /// Share of candidate files that some scanner read, rounded down. Returns 0
    /// when there are no candidates, so an empty repository is not 100% covered.
    pub fn percent(&self) -> u32 {
        if self.candidate_count == 0 {
            return 0;
        }
        ((self.distinct_read * 100) / self.candidate_count) as u32
    }
}

/// Accumulates read outcomes and tool calls per scanner.
///
/// `BTreeMap`/`BTreeSet` throughout: the four Phase 2 scanners run in parallel,
/// so any ordered output has to come from the key order rather than the arrival
/// order. Same reason the findings file sorts on a total key.
#[derive(Debug, Default)]
pub struct CoverageLedger {
    counters: BTreeMap<&'static str, ScannerCoverage>,
    read_paths: BTreeMap<&'static str, BTreeSet<String>>,
    last_outcome: BTreeMap<(&'static str, String), ReadOutcome>,
}

/// Slash-normalize so a Windows path and a POSIX path never count twice.
/// `incremental::reconcile::file_of` normalizes the same way.
fn normalize(path: &str) -> String {
    path.trim().replace('\\', "/")
}

impl CoverageLedger {
    /// Record one read attempt. Only [`ReadOutcome::Read`] counts toward
    /// coverage; the other two are holes and are tallied separately.
    pub fn record_read(&mut self, scanner: ScannerType, path: &str, outcome: ReadOutcome) {
        let name = scanner.name();
        let path = normalize(path);

        match outcome {
            ReadOutcome::Read { .. } => {
                let paths = self.read_paths.entry(name).or_default();
                paths.insert(path.clone());
                // Read the count off the set, so a re-read is not double counted.
                let distinct = paths.len();
                self.counters.entry(name).or_default().files_read = distinct;
            }
            ReadOutcome::TooLarge { .. } => self.entry(name).too_large += 1,
            ReadOutcome::Failed => self.entry(name).failed += 1,
        }

        self.last_outcome.insert((name, path), outcome);
    }

    pub fn record_listing(&mut self, scanner: ScannerType) {
        self.entry(scanner.name()).listings += 1;
    }

    pub fn record_search(&mut self, scanner: ScannerType) {
        self.entry(scanner.name()).searches += 1;
    }

    /// The outcome of the most recent read of `path` by `scanner`. The scanner
    /// loop uses this to emit `ScanEvent::FileRead` without inspecting the
    /// agent-visible result string.
    pub fn last_outcome_for(&self, scanner: ScannerType, path: &str) -> Option<ReadOutcome> {
        self.last_outcome
            .get(&(scanner.name(), normalize(path)))
            .copied()
    }

    /// Candidates that no scanner read. Input order is preserved, so pass a
    /// sorted candidate list to get a sorted result.
    pub fn never_read(&self, candidates: &[String]) -> Vec<String> {
        let read: BTreeSet<&String> = self.read_paths.values().flatten().collect();
        candidates
            .iter()
            .filter(|candidate| !read.contains(&normalize(candidate)))
            .cloned()
            .collect()
    }

    pub fn summary(&self, candidate_count: usize) -> CoverageSummary {
        let distinct: BTreeSet<&String> = self.read_paths.values().flatten().collect();
        CoverageSummary {
            candidate_count,
            distinct_read: distinct.len(),
            per_scanner: self
                .counters
                .iter()
                .map(|(name, c)| ScannerCoverage {
                    scanner: (*name).to_string(),
                    ..c.clone()
                })
                .collect(),
        }
    }

    fn entry(&mut self, name: &'static str) -> &mut ScannerCoverage {
        self.counters.entry(name).or_default()
    }
}

/// Render the ledger as `.zentra/coverage.md`.
pub fn render_markdown(summary: &CoverageSummary, never_read: &[String]) -> String {
    let mut out = String::from("# Scan Coverage\n\n");
    out.push_str(
        "This report shows what the scanners opened. A low ratio means the scan \
saw little of the code, not that the code is clean.\n\n",
    );
    out.push_str(&format!(
        "Candidate source files: {}\n\n",
        summary.candidate_count
    ));

    out.push_str("| Scanner | Files read | Too large | Failed | Listings | Searches |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    if summary.per_scanner.is_empty() {
        out.push_str("| (none) | 0 | 0 | 0 | 0 | 0 |\n");
    }
    for s in &summary.per_scanner {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            s.scanner, s.files_read, s.too_large, s.failed, s.listings, s.searches
        ));
    }

    out.push_str(&format!(
        "\nDistinct files read by any scanner: {} of {} ({}%)\n",
        summary.distinct_read,
        summary.candidate_count,
        summary.percent()
    ));

    if !never_read.is_empty() {
        out.push_str(&format!(
            "\n## Never opened ({} files)\n\n",
            never_read.len()
        ));
        for path in never_read.iter().take(MAX_NEVER_READ_LISTED) {
            out.push_str(&format!("- {path}\n"));
        }
        if never_read.len() > MAX_NEVER_READ_LISTED {
            out.push_str(&format!(
                "\nList truncated at {} of {} files.\n",
                MAX_NEVER_READ_LISTED,
                never_read.len()
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_distinct_reads_once() {
        let mut l = CoverageLedger::default();
        l.record_read(ScannerType::Sast, "src/a.rs", ReadOutcome::Read { bytes: 10 });
        l.record_read(ScannerType::Sast, "src/a.rs", ReadOutcome::Read { bytes: 10 });
        l.record_read(ScannerType::Sast, "src/b.rs", ReadOutcome::Read { bytes: 10 });

        let s = l.summary(4);
        assert_eq!(s.distinct_read, 2);
        assert_eq!(s.per_scanner.len(), 1);
        assert_eq!(s.per_scanner[0].files_read, 2);
        assert_eq!(s.per_scanner[0].scanner, "sast");
    }

    #[test]
    fn distinct_read_is_a_union_across_scanners() {
        let mut l = CoverageLedger::default();
        l.record_read(ScannerType::Sast, "src/a.rs", ReadOutcome::Read { bytes: 1 });
        l.record_read(
            ScannerType::ApiScan,
            "src/a.rs",
            ReadOutcome::Read { bytes: 1 },
        );
        l.record_read(
            ScannerType::ApiScan,
            "src/b.rs",
            ReadOutcome::Read { bytes: 1 },
        );

        let s = l.summary(2);
        assert_eq!(s.distinct_read, 2, "a union, not a sum");
        assert_eq!(s.per_scanner.len(), 2);
    }

    #[test]
    fn windows_and_posix_paths_count_once() {
        let mut l = CoverageLedger::default();
        l.record_read(ScannerType::Sast, "src\\a.rs", ReadOutcome::Read { bytes: 1 });
        l.record_read(ScannerType::Sast, "src/a.rs", ReadOutcome::Read { bytes: 1 });
        assert_eq!(l.summary(1).distinct_read, 1);
    }

    #[test]
    fn separates_holes_from_reads() {
        let mut l = CoverageLedger::default();
        l.record_read(
            ScannerType::Sast,
            "src/big.rs",
            ReadOutcome::TooLarge { bytes: 200_000 },
        );
        l.record_read(ScannerType::Sast, "src/gone.rs", ReadOutcome::Failed);

        let s = l.summary(10);
        assert_eq!(s.distinct_read, 0, "a hole is not coverage");
        assert_eq!(s.per_scanner[0].too_large, 1);
        assert_eq!(s.per_scanner[0].failed, 1);
        assert_eq!(s.per_scanner[0].files_read, 0);
    }

    #[test]
    fn counts_listings_and_searches_per_call() {
        let mut l = CoverageLedger::default();
        l.record_listing(ScannerType::Sast);
        l.record_listing(ScannerType::Sast);
        l.record_search(ScannerType::Sast);

        let s = l.summary(0);
        assert_eq!(s.per_scanner[0].listings, 2);
        assert_eq!(s.per_scanner[0].searches, 1);
    }

    #[test]
    fn percent_is_zero_when_no_candidates() {
        assert_eq!(CoverageLedger::default().summary(0).percent(), 0);
    }

    #[test]
    fn percent_rounds_down() {
        let mut l = CoverageLedger::default();
        l.record_read(ScannerType::Sast, "src/a.rs", ReadOutcome::Read { bytes: 1 });
        assert_eq!(l.summary(3).percent(), 33);
    }

    #[test]
    fn last_outcome_for_returns_the_most_recent_outcome() {
        let mut l = CoverageLedger::default();
        l.record_read(ScannerType::Sast, "src/a.rs", ReadOutcome::Failed);
        l.record_read(ScannerType::Sast, "src/a.rs", ReadOutcome::Read { bytes: 5 });

        assert_eq!(
            l.last_outcome_for(ScannerType::Sast, "src/a.rs"),
            Some(ReadOutcome::Read { bytes: 5 })
        );
        assert_eq!(l.last_outcome_for(ScannerType::Sast, "src/never.rs"), None);
        assert_eq!(
            l.last_outcome_for(ScannerType::ApiScan, "src/a.rs"),
            None,
            "outcomes are per scanner"
        );
    }

    #[test]
    fn last_outcome_for_normalizes_separators() {
        let mut l = CoverageLedger::default();
        l.record_read(ScannerType::Sast, "src\\a.rs", ReadOutcome::Read { bytes: 5 });
        assert_eq!(
            l.last_outcome_for(ScannerType::Sast, "src/a.rs"),
            Some(ReadOutcome::Read { bytes: 5 })
        );
    }

    #[test]
    fn never_read_lists_untouched_candidates() {
        let mut l = CoverageLedger::default();
        l.record_read(ScannerType::Sast, "src/a.rs", ReadOutcome::Read { bytes: 1 });
        let candidates = vec!["src/a.rs".to_string(), "src/b.rs".to_string()];
        assert_eq!(l.never_read(&candidates), vec!["src/b.rs".to_string()]);
    }

    #[test]
    fn never_read_counts_a_too_large_file_as_unread() {
        let mut l = CoverageLedger::default();
        l.record_read(
            ScannerType::Sast,
            "src/big.rs",
            ReadOutcome::TooLarge { bytes: 200_000 },
        );
        let candidates = vec!["src/big.rs".to_string()];
        assert_eq!(
            l.never_read(&candidates),
            vec!["src/big.rs".to_string()],
            "a file the agent could not read is still unread"
        );
    }

    #[test]
    fn markdown_names_the_ratio_and_truncates_the_list() {
        let mut l = CoverageLedger::default();
        l.record_read(ScannerType::Sast, "src/a.rs", ReadOutcome::Read { bytes: 1 });
        let never: Vec<String> = (0..30).map(|i| format!("src/f{i}.rs")).collect();

        let md = render_markdown(&l.summary(31), &never);

        assert!(md.contains("1 of 31 (3%)"), "got: {md}");
        assert!(md.contains("Never opened (30 files)"), "got: {md}");
        assert!(md.contains("truncated"), "got: {md}");
        assert_eq!(md.matches("- src/f").count(), 20, "got: {md}");
    }

    #[test]
    fn markdown_omits_the_never_opened_section_when_everything_was_read() {
        let mut l = CoverageLedger::default();
        l.record_read(ScannerType::Sast, "src/a.rs", ReadOutcome::Read { bytes: 1 });
        let md = render_markdown(&l.summary(1), &[]);

        assert!(md.contains("1 of 1 (100%)"), "got: {md}");
        assert!(!md.contains("Never opened"), "got: {md}");
    }

    #[test]
    fn markdown_handles_a_scan_that_read_nothing() {
        let md = render_markdown(&CoverageLedger::default().summary(12), &[]);
        assert!(md.contains("0 of 12 (0%)"), "got: {md}");
        assert!(md.contains("| (none) |"), "got: {md}");
    }
}
