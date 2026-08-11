//! Skills-as-knowledge-packs: loadable Markdown methodology files injected into
//! scanner system prompts at runtime.
//!
//! A skill is a Markdown file with optional YAML-style frontmatter. Adding a
//! methodology is a file operation, not a code change. Skills load from two
//! locations, in order of precedence:
//!
//! 1. `.zentra/skills/` — project-specific overrides (relative to the CWD).
//! 2. `~/.zentra/skills/` — user-global skills.
//!
//! Built-in skills are compiled into the binary and provide a default
//! methodology baseline. A disk file with the same name as a built-in replaces
//! it, so projects can tune or disable the defaults without a rebuild.

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::global_zentra_dir;

/// Default priority for a skill that omits the `priority` field, and for any
/// skill with no frontmatter. Lower priority values sort first (more
/// important), so the default places user skills after curated low-numbered
/// packs.
pub const DEFAULT_PRIORITY: u32 = 50;

/// Built-in skill files embedded at compile time. Each entry is a
/// `(filename, contents)` pair. A disk file with the same filename overrides
/// the built-in.
const BUILTIN_SKILLS: &[(&str, &str)] = &[
    ("sast-xss.md", include_str!("builtin/sast-xss.md")),
    ("sast-sql-injection.md", include_str!("builtin/sast-sql-injection.md")),
    ("sast-auth.md", include_str!("builtin/sast-auth.md")),
    (
        "threat-model-stride.md",
        include_str!("builtin/threat-model-stride.md"),
    ),
    ("api-bola.md", include_str!("builtin/api-bola.md")),
];

/// A loaded methodology pack. Applies to one scanner type, or to all scanners
/// when [`Skill::scanner`] is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skill {
    /// Scanner type this skill applies to (e.g. "sast"). Empty means it
    /// applies to every scanner.
    pub scanner: String,
    /// Human-readable title shown as the section heading.
    pub name: String,
    /// Sort key. Lower values sort first. Defaults to
    /// [`DEFAULT_PRIORITY`] when the frontmatter omits the field.
    pub priority: u32,
    /// The Markdown body, excluding the frontmatter.
    pub body: String,
}

impl Skill {
    /// Whether this skill applies to the given scanner. True when the scanner
    /// filter matches exactly, or when the filter is empty (applies to all).
    fn applies_to(&self, scanner_name: &str) -> bool {
        self.scanner.is_empty() || self.scanner == scanner_name
    }
}

/// Load all skills for a given scanner type from disk and the built-in set.
///
/// Searches in order of precedence:
/// 1. `.zentra/skills/` (project-specific overrides, relative to the CWD).
/// 2. `~/.zentra/skills/` (user-global skills).
/// 3. Built-in skills embedded in the binary.
///
/// A disk file with the same name as a built-in replaces the built-in. Returns
/// skills filtered for `scanner_name`, sorted by priority (lowest first).
/// Missing skills directories are not an error. Malformed files are logged and
/// skipped; a bad skill file never breaks a scan.
pub fn load_for_scanner(scanner_name: &str) -> Vec<Skill> {
    let project_dir = PathBuf::from(".zentra").join("skills");
    let global_dir = global_zentra_dir().ok().map(|d| d.join("skills"));
    load_from(Some(project_dir.as_path()), global_dir.as_deref(), scanner_name)
}

/// Render skills as a system-prompt section. Returns an empty string when
/// `skills` is empty. Each skill becomes a `### <name>` heading followed by its
/// body. Skills render in the order given, so callers must sort by priority
/// first (see [`load_for_scanner`]).
pub fn render_section(skills: &[Skill]) -> String {
    if skills.is_empty() {
        return String::new();
    }
    let mut out = String::from("## Methodology Packs\n\n");
    for skill in skills {
        out.push_str("### ");
        out.push_str(&skill.name);
        out.push('\n');
        out.push_str(skill.body.trim_end());
        out.push_str("\n\n");
    }
    // Drop the trailing blank lines; the section ends at the last body line.
    out.trim_end().to_string()
}

/// Core loader that takes explicit skills directories. Isolated from
/// [`load_for_scanner`] so tests can supply tempdirs and stay deterministic.
/// Precedence (lowest to highest): built-ins, then `global_dir`, then
/// `project_dir`. A later file with the same name replaces an earlier one.
fn load_from(
    project_dir: Option<&Path>,
    global_dir: Option<&Path>,
    scanner_name: &str,
) -> Vec<Skill> {
    let mut by_name: Vec<(String, Skill)> = Vec::new();

    // Built-ins first; disk files override them by filename below.
    for (filename, contents) in BUILTIN_SKILLS {
        upsert(&mut by_name, (*filename).to_string(), parse_skill(contents));
    }

    // Lower precedence first so higher precedence overwrites by filename.
    for dir in [global_dir, project_dir].into_iter().flatten() {
        load_dir(dir, &mut by_name);
    }

    let mut skills: Vec<Skill> = by_name
        .into_iter()
        .map(|(_, skill)| skill)
        .filter(|s| s.applies_to(scanner_name))
        .collect();
    skills.sort_by_key(|s| s.priority);
    skills
}

/// Insert a `(filename, skill)` pair, replacing an existing entry with the
/// same filename. Later loads override earlier ones by filename.
fn upsert(by_name: &mut Vec<(String, Skill)>, filename: String, skill: Skill) {
    if let Some(slot) = by_name.iter_mut().find(|(n, _)| *n == filename) {
        slot.1 = skill;
    } else {
        by_name.push((filename, skill));
    }
}

/// Recursively load every `.md` file under `dir` into `by_name`, keyed by file
/// name so later loads override earlier ones. Missing directories are the
/// common case and are silently ignored. Read errors are logged and skipped.
fn load_dir(dir: &Path, by_name: &mut Vec<(String, Skill)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        // Missing directory is the common case — not an error.
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            load_dir(&path, by_name);
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        match fs::read_to_string(&path) {
            Ok(contents) => {
                let skill = parse_skill(&contents);
                upsert(by_name, filename.to_string(), skill);
            }
            Err(e) => crate::logging::warn(
                "skills",
                format!("failed to read {}: {e}", path.display()),
            ),
        }
    }
}

/// Parse a skill file's contents into a [`Skill`]. Frontmatter is optional and
/// sits between leading `---` markers. Missing or malformed fields fall back to
/// defaults; the file is never fatal to a scan.
fn parse_skill(contents: &str) -> Skill {
    let (frontmatter, body) = split_frontmatter(contents);
    let mut skill = Skill {
        scanner: String::new(),
        name: String::new(),
        priority: DEFAULT_PRIORITY,
        body,
    };
    for line in frontmatter.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "scanner" => skill.scanner = value.to_string(),
            "name" => skill.name = unquote(value),
            "priority" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    skill.priority = parsed;
                }
            }
            _ => {}
        }
    }
    skill
}

/// Split a file into `(frontmatter, body)`. Frontmatter is the text between the
/// first `---` marker and the next `---` marker, when the file starts with one.
/// When there is no leading `---`, the frontmatter is empty and the body is the
/// whole file. A missing closing marker is treated as "no frontmatter". The
/// body is sliced from the original bytes so trailing newlines are preserved.
fn split_frontmatter(contents: &str) -> (String, String) {
    let lines: Vec<&str> = contents.lines().collect();
    if lines.first().map(|l| l.trim()) != Some("---") {
        return (String::new(), contents.to_string());
    }
    // Find the closing marker (a line after the opening one).
    let Some(close_idx) = (1..lines.len()).find(|&i| lines[i].trim() == "---") else {
        // No closing marker: treat the whole file as the body.
        return (String::new(), contents.to_string());
    };
    let frontmatter = lines[1..close_idx].join("\n");
    // Body: the original bytes from the first line after the closing marker.
    // Drop leading blank lines (cosmetic); keep trailing newlines intact.
    let body = contents[line_start(contents, close_idx + 1)..]
        .trim_start_matches('\n')
        .to_string();
    (frontmatter, body)
}

/// Byte offset in `contents` where the line at index `idx` (0-based, matching
/// `str::lines`) begins. Counts `\n`, `\r`, and `\r\n` as single terminators.
fn line_start(contents: &str, idx: usize) -> usize {
    if idx == 0 {
        return 0;
    }
    let bytes = contents.as_bytes();
    let mut offset = 0usize;
    let mut current_line = 0usize;
    while current_line < idx && offset < bytes.len() {
        match bytes[offset] {
            b'\n' => {
                current_line += 1;
                offset += 1;
            }
            b'\r' => {
                current_line += 1;
                offset += 1;
                if offset < bytes.len() && bytes[offset] == b'\n' {
                    offset += 1;
                }
            }
            _ => offset += 1,
        }
    }
    offset
}

/// Remove surrounding matching quotes from a frontmatter value, if present.
/// Handles both `"..."` and `'...'`.
fn unquote(value: &str) -> String {
    let v = value.trim();
    let bytes = v.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[0] == bytes[bytes.len() - 1]
    {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_well_formed_skill_with_all_fields() {
        let contents = "---\nscanner: sast\nname: \"XSS Detection\"\npriority: 10\n---\nLook for innerHTML.\n";
        let skill = parse_skill(contents);
        assert_eq!(skill.scanner, "sast");
        assert_eq!(skill.name, "XSS Detection");
        assert_eq!(skill.priority, 10);
        assert_eq!(skill.body, "Look for innerHTML.\n");
    }

    #[test]
    fn parse_skill_with_no_frontmatter_uses_defaults() {
        let contents = "This is the body.\nSecond line.\n";
        let skill = parse_skill(contents);
        assert_eq!(skill.scanner, "");
        assert_eq!(skill.name, "");
        assert_eq!(skill.priority, DEFAULT_PRIORITY);
        assert_eq!(skill.body, contents);
    }

    #[test]
    fn parse_skill_missing_priority_defaults_to_50() {
        let contents = "---\nscanner: api_scan\nname: BOLA\n---\nbody text\n";
        let skill = parse_skill(contents);
        assert_eq!(skill.priority, DEFAULT_PRIORITY);
        assert_eq!(skill.scanner, "api_scan");
        assert_eq!(skill.name, "BOLA");
        assert_eq!(skill.body, "body text\n");
    }

    #[test]
    fn render_section_empty_returns_empty_string() {
        assert_eq!(render_section(&[]), "");
    }

    #[test]
    fn render_section_lists_header_and_each_skill_name() {
        let skills = vec![
            Skill {
                scanner: "sast".to_string(),
                name: "XSS Detection".to_string(),
                priority: 1,
                body: "Look for innerHTML.".to_string(),
            },
            Skill {
                scanner: "sast".to_string(),
                name: "SQL Injection".to_string(),
                priority: 2,
                body: "Look for concatenation.".to_string(),
            },
        ];
        let out = render_section(&skills);
        assert!(out.contains("## Methodology Packs"), "got: {out}");
        assert!(out.contains("### XSS Detection"), "got: {out}");
        assert!(out.contains("### SQL Injection"), "got: {out}");
        assert!(out.contains("Look for innerHTML."), "got: {out}");
        assert!(out.contains("Look for concatenation."), "got: {out}");
    }

    #[test]
    fn load_from_sorts_skills_by_priority_lowest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let skills_dir = tmp.path().join("skills");
        fs::create_dir_all(&skills_dir).unwrap();
        fs::write(
            skills_dir.join("a.md"),
            "---\nscanner: sast\nname: \"Late\"\npriority: 90\n---\nbody\n",
        )
        .unwrap();
        fs::write(
            skills_dir.join("b.md"),
            "---\nscanner: sast\nname: \"Early\"\npriority: 5\n---\nbody\n",
        )
        .unwrap();
        fs::write(
            skills_dir.join("c.md"),
            "---\nscanner: sast\nname: \"Mid\"\npriority: 50\n---\nbody\n",
        )
        .unwrap();

        let skills = load_from(Some(skills_dir.as_path()), None, "sast");
        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names.first(), Some(&"Early"), "lowest priority first: {names:?}");
        assert_eq!(names.last(), Some(&"Late"), "highest priority last: {names:?}");
    }

    #[test]
    fn load_from_filters_by_scanner_name() {
        let tmp = tempfile::tempdir().unwrap();
        let skills_dir = tmp.path().join("skills");
        fs::create_dir_all(&skills_dir).unwrap();
        fs::write(
            skills_dir.join("proj-sast.md"),
            "---\nscanner: sast\nname: \"Proj SAST\"\npriority: 1\n---\nbody\n",
        )
        .unwrap();
        fs::write(
            skills_dir.join("proj-api.md"),
            "---\nscanner: api_scan\nname: \"Proj API\"\npriority: 2\n---\nbody\n",
        )
        .unwrap();

        let api_skills = load_from(Some(skills_dir.as_path()), None, "api_scan");
        assert!(
            api_skills.iter().any(|s| s.name == "Proj API"),
            "api_scan should see the API skill: {api_skills:?}"
        );
        assert!(
            api_skills.iter().all(|s| s.scanner != "sast"),
            "api_scan must not see sast skills: {api_skills:?}"
        );
    }

    #[test]
    fn untagged_skill_appears_for_all_scanners() {
        let tmp = tempfile::tempdir().unwrap();
        let skills_dir = tmp.path().join("skills");
        fs::create_dir_all(&skills_dir).unwrap();
        fs::write(
            skills_dir.join("general.md"),
            "---\nname: \"General\"\npriority: 5\n---\nbody\n",
        )
        .unwrap();

        for scanner in ["sast", "api_scan", "threat_model", "iac_scan"] {
            let skills = load_from(Some(skills_dir.as_path()), None, scanner);
            assert!(
                skills.iter().any(|s| s.name == "General"),
                "General skill missing for {scanner}: {skills:?}"
            );
        }
    }

    #[test]
    fn disk_file_overrides_builtin_with_same_filename() {
        let tmp = tempfile::tempdir().unwrap();
        let skills_dir = tmp.path().join("skills");
        fs::create_dir_all(&skills_dir).unwrap();
        // Same filename as a built-in, but a different body.
        fs::write(
            skills_dir.join("sast-xss.md"),
            "---\nscanner: sast\nname: \"Override\"\npriority: 1\n---\noverridden body\n",
        )
        .unwrap();

        let skills = load_from(Some(skills_dir.as_path()), None, "sast");
        let xss = skills
            .iter()
            .find(|s| s.name == "Override")
            .expect("override should win over builtin");
        assert_eq!(xss.body, "overridden body\n");
        // The original built-in name must not also appear.
        assert!(
            skills.iter().all(|s| s.name != "XSS Detection Patterns"),
            "builtin should be replaced: {skills:?}"
        );
    }

    #[test]
    fn unquote_strips_matching_quotes() {
        assert_eq!(unquote("\"hello\""), "hello");
        assert_eq!(unquote("'hello'"), "hello");
        assert_eq!(unquote("hello"), "hello");
        assert_eq!(unquote("\"unclosed"), "\"unclosed");
    }

    #[test]
    fn parse_skill_ignores_malformed_priority() {
        let contents = "---\nscanner: sast\nname: \"X\"\npriority: not-a-number\n---\nbody\n";
        let skill = parse_skill(contents);
        assert_eq!(skill.priority, DEFAULT_PRIORITY);
    }

    #[test]
    fn split_frontmatter_without_closing_marker_treats_whole_file_as_body() {
        let contents = "---\nscanner: sast\nname: \"X\"\nno closing marker\nbody line\n";
        let (fm, body) = split_frontmatter(contents);
        assert_eq!(fm, "");
        assert_eq!(body, contents);
    }
}
