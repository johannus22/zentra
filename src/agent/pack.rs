//! Whole-repository packing — the third compaction mode.
//!
//! The default mode is agentic exploration: the agent calls `list_files`, then
//! `grep_code`, then `read_file`, and finds what it navigates to. That gives no
//! coverage guarantee, and `.zentra/coverage.md` exists to measure the gap.
//!
//! Pack mode removes the navigation. It filters the repository down to
//! security-relevant source, concatenates it, and hands the whole thing to the
//! scanner as its opening message. If a file is in the pack, the model saw it.
//! Cross-file reasoning is where an LLM beats a deterministic analyzer, and this
//! mode pays tokens to get it instead of paying static-analysis engineering.
//!
//! It only works when the filtered repository fits the input budget. When it does
//! not, the mode refuses rather than silently truncating: a half-packed repo has
//! the coverage problem back, minus the honesty. There is no chunking here on
//! purpose — chunking is where cross-file reasoning degrades, and a wrong answer
//! that looks whole is worse than a clear refusal.

use std::path::Path;

use crate::agent::context_budget;
use crate::provider::{AgentMessage, ToolDefinition};
use crate::tools::fs_tools;

/// Per-file byte cap. Matches `fs_tools::read_file`, so the pack never contains
/// a file the agent could not have read for itself.
const MAX_FILE_BYTES: usize = 100_000;

/// Why a candidate file did not make it into the pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// Excluded by a filter rule (tests, docs, vendored, generated, lockfile).
    Filtered,
    /// Over [`MAX_FILE_BYTES`].
    TooLarge,
    /// Unreadable or not valid UTF-8.
    Unreadable,
}

#[derive(Debug, Clone)]
pub struct PackedFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Default)]
pub struct RepoPack {
    pub files: Vec<PackedFile>,
    /// Candidate files that did not make it in, with the reason.
    pub skipped: Vec<(String, SkipReason)>,
    /// Every candidate the walker found, before filtering.
    pub candidate_count: usize,
}

impl RepoPack {
    pub fn total_bytes(&self) -> usize {
        self.files.iter().map(|f| f.content.len()).sum()
    }

    pub fn skipped_for(&self, reason: SkipReason) -> usize {
        self.skipped.iter().filter(|(_, r)| *r == reason).count()
    }

    /// The packed text, one delimited section per file.
    ///
    /// Paths are echoed verbatim so a finding can cite `file:line`. The delimiter
    /// is a fence the scanned content cannot forge a way out of by accident: any
    /// line the file itself contains is still inside its own section, because the
    /// reader keys on the `=== FILE:` prefix at line start.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.total_bytes() + self.files.len() * 64);
        out.push_str(
            "The complete filtered source of this repository follows. Every file you \
need is already here.\n\nDo not call list_files. Read a file again with read_file only if \
you need a part that was skipped. Cite findings as path:line using the paths below.\n\n",
        );
        for file in &self.files {
            out.push_str(&format!("=== FILE: {} ===\n", file.path));
            out.push_str(&file.content);
            if !file.content.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
        }
        out.push_str(&format!(
            "=== END OF PACK: {} files, {} bytes ===\n",
            self.files.len(),
            self.total_bytes()
        ));
        out
    }

    /// Estimated input tokens for a scanner's first request carrying this pack.
    pub fn estimate_tokens(&self, system: &str, tools: &[ToolDefinition]) -> usize {
        let messages = vec![AgentMessage::User(self.render())];
        context_budget::estimate_tokens(system, &messages, tools)
    }
}

/// True when `path` is security-relevant source worth packing.
///
/// Excludes what the CodeCrucible write-up excludes — tests, documentation,
/// vendored dependencies, generated artifacts, lockfiles — because they cost
/// tokens without changing a verdict. Protocol and schema files stay in even
/// under an excluded directory: they define trust boundaries.
pub fn include_in_pack(path: &str) -> bool {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(&lower).to_string();

    // Trust-boundary definitions are always in, wherever they live.
    if lower.ends_with(".proto") || lower.ends_with(".sql") || lower.ends_with(".graphql") {
        return true;
    }

    if !fs_tools::is_source_file(&lower) {
        return false;
    }

    // Lockfiles: the SupplyChain scanner reads manifests through run_audit, so a
    // lockfile in the pack is thousands of tokens that change no verdict.
    const LOCKFILES: &[&str] = &[
        "cargo.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "composer.lock",
        "gemfile.lock",
        "go.sum",
    ];
    if LOCKFILES.contains(&file_name.as_str()) {
        return false;
    }

    // Vendored, generated, and build output.
    const EXCLUDED_SEGMENTS: &[&str] = &[
        "node_modules",
        "vendor",
        "third_party",
        "thirdparty",
        "target",
        "dist",
        "build",
        "out",
        "coverage",
        "__pycache__",
        ".venv",
        "venv",
        "site-packages",
        "migrations",
    ];
    if lower
        .split('/')
        .any(|segment| EXCLUDED_SEGMENTS.contains(&segment))
    {
        return false;
    }

    // Tests and fixtures. A finding in a test is not reachable from untrusted
    // input, which is exactly what the screening pass would dispute anyway.
    const TEST_SEGMENTS: &[&str] = &["tests", "test", "spec", "specs", "fixtures", "__tests__", "testdata", "e2e"];
    if lower
        .split('/')
        .any(|segment| TEST_SEGMENTS.contains(&segment))
    {
        return false;
    }
    if file_name.starts_with("test_")
        || file_name.contains("_test.")
        || file_name.contains(".test.")
        || file_name.contains(".spec.")
        || file_name.contains("_spec.")
    {
        return false;
    }

    // Documentation and generated/minified artifacts.
    if lower.split('/').any(|segment| segment == "docs" || segment == "doc") {
        return false;
    }
    if file_name.contains(".min.") || file_name.ends_with(".pb.go") || file_name.ends_with("_pb2.py")
    {
        return false;
    }

    true
}

/// Build a pack from every source file under `root`.
///
/// Never errors: an unreadable or oversized file is recorded in `skipped` rather
/// than failing the run, so one bad file cannot cost the whole scan. The file
/// order comes from [`fs_tools::source_file_paths`], which sorts — the same pack
/// is produced twice for the same tree.
pub fn build_pack(root: &Path) -> RepoPack {
    let candidates = fs_tools::source_file_paths(root);
    let mut pack = RepoPack {
        candidate_count: candidates.len(),
        ..Default::default()
    };

    for relative in candidates {
        if !include_in_pack(&relative) {
            pack.skipped.push((relative, SkipReason::Filtered));
            continue;
        }

        let full = root.join(&relative);
        match std::fs::metadata(&full) {
            Ok(meta) if meta.len() as usize > MAX_FILE_BYTES => {
                pack.skipped.push((relative, SkipReason::TooLarge));
                continue;
            }
            Ok(_) => {}
            Err(_) => {
                pack.skipped.push((relative, SkipReason::Unreadable));
                continue;
            }
        }

        match std::fs::read_to_string(&full) {
            Ok(content) => pack.files.push(PackedFile {
                path: relative,
                content,
            }),
            Err(_) => pack.skipped.push((relative, SkipReason::Unreadable)),
        }
    }

    pack
}

/// Whether a pack of `estimate` tokens fits a scanner's first request.
pub fn fits_budget(estimate: usize, context_window: u32, max_output: u32) -> bool {
    estimate <= context_budget::input_budget(context_window, max_output)
}

/// The operator-facing summary printed for `--pack` and `--pack --dry-run`.
pub fn render_summary(
    pack: &RepoPack,
    estimate: usize,
    context_window: u32,
    max_output: u32,
) -> String {
    let budget = context_budget::input_budget(context_window, max_output);
    let verdict = if estimate <= budget {
        "fits".to_string()
    } else {
        format!("does NOT fit — over by ~{} tokens", estimate - budget)
    };

    format!(
        "Pack mode\n  \
Packed:     {} of {} candidate files ({} bytes)\n  \
Skipped:    {} filtered, {} too large, {} unreadable\n  \
Estimate:   ~{} input tokens per scanner\n  \
Budget:     {} tokens (context {} minus {} reserved for output, 85% margin)\n  \
Verdict:    {}",
        pack.files.len(),
        pack.candidate_count,
        pack.total_bytes(),
        pack.skipped_for(SkipReason::Filtered),
        pack.skipped_for(SkipReason::TooLarge),
        pack.skipped_for(SkipReason::Unreadable),
        estimate,
        budget,
        context_window,
        max_output,
        verdict,
    )
}

/// The refusal message shown when the pack does not fit.
pub fn refusal_message(estimate: usize, context_window: u32, max_output: u32) -> String {
    let budget = context_budget::input_budget(context_window, max_output);
    format!(
        "Pack mode refused: the filtered repository needs ~{estimate} input tokens but the \
budget is {budget} (context {context_window} minus {max_output} reserved for output).\n\n\
Pack mode does not chunk on purpose — a partial pack has the same blind spots as a normal \
scan without saying so.\n\nOptions:\n  \
- Run the normal scan: zentra scan\n  \
- Use a larger-context profile, then retry --pack\n  \
- Narrow target_path in .zentra/config.json to one service, then --pack that"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn repo(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        for (path, body) in files {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, body).unwrap();
        }
        dir
    }

    #[test]
    fn includes_plain_source() {
        assert!(include_in_pack("src/main.rs"));
        assert!(include_in_pack("web/app.tsx"));
        assert!(include_in_pack("infra/main.tf"));
    }

    #[test]
    fn excludes_tests_and_fixtures() {
        assert!(!include_in_pack("tests/agent_test.rs"));
        assert!(!include_in_pack("src/db_test.go"));
        assert!(!include_in_pack("web/app.test.ts"));
        assert!(!include_in_pack("web/app.spec.ts"));
        assert!(!include_in_pack("spec/models/user.rb.json"));
        assert!(!include_in_pack("src/fixtures/sample.json"));
        assert!(!include_in_pack("e2e/login.ts"));
        assert!(!include_in_pack("src/test_helpers.py"));
    }

    #[test]
    fn excludes_vendored_generated_and_build_output() {
        assert!(!include_in_pack("node_modules/left-pad/index.js"));
        assert!(!include_in_pack("vendor/github.com/x/y.go"));
        assert!(!include_in_pack("target/debug/build.rs"));
        assert!(!include_in_pack("dist/bundle.js"));
        assert!(!include_in_pack("web/vendor.min.js"));
        assert!(!include_in_pack("api/service.pb.go"));
        assert!(!include_in_pack("api/service_pb2.py"));
        assert!(!include_in_pack("docs/guide.json"));
    }

    #[test]
    fn excludes_lockfiles_but_keeps_manifests() {
        assert!(!include_in_pack("Cargo.lock"));
        assert!(!include_in_pack("package-lock.json"));
        assert!(!include_in_pack("go.sum"));
        assert!(include_in_pack("Cargo.toml"), "a manifest is still source");
        assert!(include_in_pack("package.json"));
    }

    #[test]
    fn keeps_trust_boundary_definitions_even_under_an_excluded_path() {
        assert!(include_in_pack("vendor/api/service.proto"));
        assert!(include_in_pack("tests/schema.sql"));
        assert!(include_in_pack("docs/api.graphql"));
    }

    #[test]
    fn excludes_non_source_entirely() {
        assert!(!include_in_pack("assets/logo.png"));
        assert!(!include_in_pack("README"));
    }

    #[test]
    fn build_pack_collects_source_and_records_filtered_files() {
        let dir = repo(&[
            ("src/main.rs", "fn main() {}"),
            ("src/lib.rs", "pub fn x() {}"),
            ("tests/it.rs", "fn t() {}"),
            ("package-lock.json", "{}"),
            // `.lock` is not a source extension, so a Cargo.lock never even
            // reaches the pack filter — `source_file_paths` drops it first.
            ("Cargo.lock", "[[package]]"),
        ]);

        let pack = build_pack(dir.path());

        let packed: Vec<&str> = pack.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(packed, vec!["src/lib.rs", "src/main.rs"], "sorted, filtered");
        assert_eq!(pack.candidate_count, 4, "Cargo.lock is not a candidate");
        assert_eq!(
            pack.skipped_for(SkipReason::Filtered),
            2,
            "tests/it.rs and package-lock.json"
        );
        assert_eq!(pack.total_bytes(), "fn main() {}".len() + "pub fn x() {}".len());
    }

    #[test]
    fn build_pack_is_deterministic() {
        let dir = repo(&[
            ("src/z.rs", "fn z() {}"),
            ("src/a.rs", "fn a() {}"),
            ("src/m.rs", "fn m() {}"),
        ]);

        assert_eq!(build_pack(dir.path()).render(), build_pack(dir.path()).render());
    }

    #[test]
    fn build_pack_skips_an_oversized_file_without_failing() {
        let dir = repo(&[
            ("src/ok.rs", "fn ok() {}"),
            ("src/huge.rs", &"x".repeat(MAX_FILE_BYTES + 1)),
        ]);

        let pack = build_pack(dir.path());

        assert_eq!(pack.files.len(), 1);
        assert_eq!(pack.files[0].path, "src/ok.rs");
        assert_eq!(pack.skipped_for(SkipReason::TooLarge), 1);
    }

    #[test]
    fn build_pack_skips_non_utf8_without_failing() {
        let dir = repo(&[("src/ok.rs", "fn ok() {}")]);
        std::fs::write(dir.path().join("src/bad.rs"), [0xff, 0xfe, 0x00, 0x9f]).unwrap();

        let pack = build_pack(dir.path());

        assert_eq!(pack.files.len(), 1, "one bad file must not empty the pack");
        assert_eq!(pack.skipped_for(SkipReason::Unreadable), 1);
    }

    #[test]
    fn render_names_every_file_and_closes_the_pack() {
        let dir = repo(&[("src/a.rs", "fn a() {}"), ("src/b.rs", "fn b() {}")]);
        let rendered = build_pack(dir.path()).render();

        assert!(rendered.contains("=== FILE: src/a.rs ==="), "got:\n{rendered}");
        assert!(rendered.contains("=== FILE: src/b.rs ==="), "got:\n{rendered}");
        assert!(rendered.contains("fn a() {}"));
        assert!(rendered.contains("=== END OF PACK: 2 files"), "got:\n{rendered}");
        assert!(rendered.contains("Do not call list_files"));
    }

    #[test]
    fn render_terminates_a_file_missing_its_trailing_newline() {
        let dir = repo(&[("src/a.rs", "no newline at end")]);
        let rendered = build_pack(dir.path()).render();
        assert!(
            rendered.contains("no newline at end\n\n=== END OF PACK"),
            "the next delimiter must start at a line boundary:\n{rendered}"
        );
    }

    #[test]
    fn estimate_grows_with_the_pack() {
        let small = repo(&[("src/a.rs", "fn a() {}")]);
        let large = repo(&[("src/a.rs", &"// filler\n".repeat(2_000))]);

        assert!(
            build_pack(large.path()).estimate_tokens("sys", &[])
                > build_pack(small.path()).estimate_tokens("sys", &[])
        );
    }

    #[test]
    fn fits_budget_matches_the_context_budget_rule() {
        // (200_000 - 4096) * 85 / 100 = 166_518
        assert!(fits_budget(166_518, 200_000, 4096));
        assert!(!fits_budget(166_519, 200_000, 4096));
    }

    #[test]
    fn summary_reports_the_verdict_both_ways() {
        let dir = repo(&[("src/a.rs", "fn a() {}")]);
        let pack = build_pack(dir.path());

        let ok = render_summary(&pack, 1_000, 200_000, 4096);
        assert!(ok.contains("Verdict:    fits"), "got:\n{ok}");
        assert!(ok.contains("1 of 1 candidate files"), "got:\n{ok}");

        let bad = render_summary(&pack, 999_999, 200_000, 4096);
        assert!(bad.contains("does NOT fit"), "got:\n{bad}");
        assert!(bad.contains("over by ~833481 tokens"), "got:\n{bad}");
    }

    #[test]
    fn refusal_names_the_numbers_and_the_alternatives() {
        let message = refusal_message(500_000, 200_000, 4096);
        assert!(message.contains("~500000 input tokens"), "got:\n{message}");
        assert!(message.contains("166518"), "got:\n{message}");
        assert!(message.contains("zentra scan"), "got:\n{message}");
        assert!(message.contains("does not chunk"), "got:\n{message}");
    }
}
