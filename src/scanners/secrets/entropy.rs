// src/scanners/secrets/entropy.rs
use std::sync::OnceLock;
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub struct EntropyHit {
    pub token: String,
    pub entropy: f64,
    pub detector: String,
}

pub fn score(s: &str) -> f64 {
    shannon_entropy(s)
}

fn shannon_entropy(s: &str) -> f64 {
    let bytes = s.as_bytes();
    let len = bytes.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn base64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap())
}

fn hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[0-9a-fA-F]{32,}\b").unwrap())
}

fn alphanum_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[A-Za-z0-9_\-]{20,}\b").unwrap())
}

pub fn scan_line_for_high_entropy(line: &str) -> Vec<EntropyHit> {
    // Skip lines with no run of 20+ consecutive non-whitespace bytes — they can't match any entropy threshold
    if !line.as_bytes().windows(20).any(|w| w.iter().all(|&b| b > b' ')) {
        return Vec::new();
    }
    let mut results: Vec<EntropyHit> = Vec::new();
    let mut covered: Vec<(usize, usize)> = Vec::new();

    for m in base64_re().find_iter(line) {
        let s = m.as_str();
        let e = shannon_entropy(s);
        if e > 4.5 {
            covered.push((m.start(), m.end()));
            results.push(EntropyHit {
                token: s.to_string(),
                entropy: e,
                detector: "high_entropy_base64".to_string(),
            });
        }
    }

    for m in hex_re().find_iter(line) {
        if covered.iter().any(|(s, e)| m.start() < *e && m.end() > *s) {
            continue;
        }
        let s = m.as_str();
        let e = shannon_entropy(s);
        if e > 3.0 {
            covered.push((m.start(), m.end()));
            results.push(EntropyHit {
                token: s.to_string(),
                entropy: e,
                detector: "high_entropy_hex".to_string(),
            });
        }
    }

    for m in alphanum_re().find_iter(line) {
        if covered.iter().any(|(s, e)| m.start() < *e && m.end() > *s) {
            continue;
        }
        let s = m.as_str();
        let e = shannon_entropy(s);
        if e > 3.5 {
            covered.push((m.start(), m.end()));
            results.push(EntropyHit {
                token: s.to_string(),
                entropy: e,
                detector: "high_entropy_alphanum".to_string(),
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_base64_token_scores_above_threshold() {
        // A high-entropy base64 string (32 random-looking bytes encoded)
        let s = "dGhpcyBpcyBhIHRlc3QgdG9rZW4hMTIzNDU2";
        assert!(score(s) > 4.5, "expected entropy > 4.5, got {:.2}", score(s));
    }

    #[test]
    fn all_same_char_scores_zero() {
        let s = "aaaaaaaaaaaaaaaaaaaaaa";
        assert!(score(s) < 0.01, "all-same-char string should have zero entropy");
    }

    #[test]
    fn low_entropy_string_below_threshold() {
        let s = "abcabcabcabcabcabcabc";
        assert!(score(s) < 2.0, "repeated pattern should have low entropy");
    }

    #[test]
    fn scan_line_finds_high_entropy_base64() {
        let line = r#"secret = "dGhpcyBpcyBhIHRlc3QgdG9rZW4hMTIzNDU2""#;
        let hits = scan_line_for_high_entropy(line);
        assert!(!hits.is_empty(), "expected at least one entropy hit");
        assert!(hits.iter().any(|h| h.detector.contains("base64")));
    }

    #[test]
    fn all_zeros_hex_not_flagged() {
        let line = "sha256: 0000000000000000000000000000000000000000000000000000000000000000";
        let hits = scan_line_for_high_entropy(line);
        let hex_hits: Vec<_> = hits.iter().filter(|h| h.detector.contains("hex")).collect();
        assert!(hex_hits.is_empty(), "all-zero hex should not be flagged");
    }

    #[test]
    fn short_line_skipped_by_guard() {
        // All tokens < 20 chars — guard returns early
        let line = "let x = 5; // short";
        let hits = scan_line_for_high_entropy(line);
        assert!(hits.is_empty(), "short line should produce no entropy hits");
    }

    #[test]
    fn line_with_only_spaces_skipped() {
        let line = "    ";
        let hits = scan_line_for_high_entropy(line);
        assert!(hits.is_empty());
    }

    #[test]
    fn deduplicates_overlapping_matches() {
        // base64 match should prevent the same region being flagged as alphanum
        let line = "token=dGhpcyBpcyBhIHRlc3QgdG9rZW4hMTIzNDU2";
        let hits = scan_line_for_high_entropy(line);
        let tokens: std::collections::HashSet<_> = hits.iter().map(|h| h.token.as_str()).collect();
        // Should not return the same substring under multiple detector names
        assert_eq!(tokens.len(), hits.len(), "duplicate tokens should be de-covered");
    }
}
