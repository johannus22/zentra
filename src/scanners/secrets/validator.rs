use super::{allowlist::Allowlist, SecretsMatch};

pub struct ContextValidator<'a> {
    allowlist: &'a Allowlist,
}

impl<'a> ContextValidator<'a> {
    pub fn new(allowlist: &'a Allowlist) -> Self {
        Self { allowlist }
    }

    /// Returns Some(reason) if the match should be suppressed, None if it is a real finding.
    pub fn check(
        &self,
        m: &SecretsMatch,
        current_line: &str,
        prev_line: Option<&str>,
    ) -> Option<String> {
        // Rule 1: Test directory
        let f = m.file.replace('\\', "/").to_lowercase();
        if f.contains("/test/")
            || f.contains("/tests/")
            || f.contains("/spec/")
            || f.contains("/mock/")
            || f.contains("/__test__/")
            || f.starts_with("test/")
            || f.starts_with("tests/")
            || f.starts_with("spec/")
            || f.starts_with("mock/")
            || f.starts_with("__test__/")
        {
            return Some("test_directory".to_string());
        }

        // Rule 2: Placeholder value
        let r = m.redacted.to_lowercase();
        let placeholders = [
            "your_", "example", "placeholder", "xxx", "yyy", "dummy",
            "fake", "todo", "changeme", "replace", "insert", "add_your",
        ];
        if placeholders.iter().any(|p| r.contains(p))
            || r.starts_with('<')
            || r.contains('>')
            || is_all_same_char(&m.redacted)
        {
            return Some("placeholder_value".to_string());
        }

        // Rule 3: Inline annotation on current or previous line
        if current_line.contains("zentra:ignore") {
            return Some("inline_annotation".to_string());
        }
        if prev_line.map(|l| l.contains("zentra:ignore")).unwrap_or(false) {
            return Some("inline_annotation".to_string());
        }

        // Rule 4: Variable name only (secret extracted looks like an identifier, not a literal)
        if is_identifier_like(&m.redacted) {
            return Some("variable_name_only".to_string());
        }

        // Rule 5: Allowlist fingerprint
        if self.allowlist.is_fingerprint_allowed(&m.file, m.line, &m.redacted) {
            return Some("allowlist_fingerprint".to_string());
        }

        // Rule 6: Allowlist path glob
        if self.allowlist.is_path_allowed(&m.file) {
            return Some("allowlist_path".to_string());
        }

        // Rule 7: Allowlist detector+path entry
        if self.allowlist.is_entry_allowed(&m.detector, &m.file) {
            return Some("allowlist_entry".to_string());
        }

        // Rule 8: Common non-secret values (localhost, booleans, common identifiers)
        if is_common_non_secret(&m.redacted) {
            return Some("common_non_secret".to_string());
        }

        // Rule 9: Date formats (MM-DD-YYYY, YYYY-MM-DD, etc.)
        if is_date_format(&m.redacted) {
            return Some("date_format".to_string());
        }

        // Rule 10: Version strings (v1.2.3, 1.0.0-beta, etc.)
        if is_version_string(&m.redacted) {
            return Some("version_string".to_string());
        }

        None
    }
}

fn is_all_same_char(s: &str) -> bool {
    s.chars().count() > 3 && {
        let mut it = s.chars();
        let first = it.next().unwrap();
        it.all(|c| c == first)
    }
}

fn is_identifier_like(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.chars().next().unwrap();
    if !first.is_alphabetic() && first != '_' {
        return false;
    }
    let all_word = s.chars().all(|c| c.is_alphanumeric() || c == '_');
    if !all_word {
        return false;
    }
    // If fewer than 3 digits, treat as identifier (real secrets have more digits)
    let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
    digit_count < 3
}

fn is_common_non_secret(s: &str) -> bool {
    let lower = s.to_lowercase();
    // Common non-secret values that appear in code literals
    let non_secrets = [
        "localhost", "127.0.0.1", "0.0.0.0", "::1",
        "true", "false", "yes", "no", "on", "off", "null", "undefined", "none",
        "admin", "root", "guest", "user", "test", "demo", "example", "default",
        "password", "changeme", "pass", "secret",
        "date", "version", "name", "id", "title", "description", "label",
        "path", "url", "host", "port", "protocol", "scheme",
        "get", "post", "put", "delete", "patch", "head", "options",
        "application", "json", "xml", "html", "text", "csv",
    ];
    non_secrets.iter().any(|ns| lower == *ns)
}

fn is_date_format(s: &str) -> bool {
    // Match patterns like MM-DD-YYYY, YYYY-MM-DD, dd/mm/yyyy, ISO dates
    let date_patterns = [
        r"^\d{2}-\d{2}-\d{4}$",      // MM-DD-YYYY or DD-MM-YYYY
        r"^\d{4}-\d{2}-\d{2}$",      // YYYY-MM-DD
        r"^\d{2}/\d{2}/\d{4}$",      // MM/DD/YYYY or DD/MM/YYYY
        r"^\d{4}/\d{2}/\d{2}$",      // YYYY/MM/DD
        r"^\d{2}\.\d{2}\.\d{4}$",    // DD.MM.YYYY
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", // ISO 8601
        r"^\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}", // 1 Jan 2024
    ];
    date_patterns.iter().any(|pat| {
        regex::Regex::new(pat).map(|re| re.is_match(s)).unwrap_or(false)
    })
}

fn is_version_string(s: &str) -> bool {
    // Match semantic version patterns: v1.2.3, 1.0.0, 1.0.0-beta, 2024.1.0, etc.
    let version_patterns = [
        r"^v?\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?$",  // v1.2.3, 1.0.0-beta
        r"^\d{4}\.\d+\.\d+$",                           // 2024.1.0
    ];
    version_patterns.iter().any(|pat| {
        regex::Regex::new(pat).map(|re| re.is_match(s)).unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::secrets::allowlist::Allowlist;
    use tempfile::TempDir;

    fn make_match(file: &str, redacted: &str, detector: &str) -> SecretsMatch {
        SecretsMatch {
            file: file.to_string(),
            line: 42,
            commit: None,
            detector: detector.to_string(),
            entropy: Some(4.8),
            redacted: redacted.to_string(),
            suppressed: false,
            suppression_reason: None,
        }
    }

    fn no_allowlist() -> Allowlist {
        let dir = TempDir::new().unwrap();
        Allowlist::load(dir.path())
    }

    #[test]
    fn suppresses_test_directory() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("tests/fixtures/config.rs", "AKIA...MPLE", "aws_access_key");
        assert_eq!(v.check(&m, "", None), Some("test_directory".to_string()));
    }

    #[test]
    fn suppresses_spec_directory() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("spec/unit/config.rb", "AKIA...MPLE", "aws_access_key");
        assert_eq!(v.check(&m, "", None), Some("test_directory".to_string()));
    }

    #[test]
    fn suppresses_placeholder_value() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("src/config.rs", "your_api_key_here", "aws_access_key");
        assert_eq!(v.check(&m, "", None), Some("placeholder_value".to_string()));
    }

    #[test]
    fn suppresses_all_same_char() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("src/config.rs", "aaaaaaaaaaaaaaaaaaa", "aws_access_key");
        assert_eq!(v.check(&m, "", None), Some("placeholder_value".to_string()));
    }

    #[test]
    fn suppresses_inline_annotation_on_current_line() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("src/config.rs", "AKIA...MPLE", "aws_access_key");
        let line = r#"api_key = "AKIAIOSFODNN7EXAMPLE" # zentra:ignore"#;
        assert_eq!(v.check(&m, line, None), Some("inline_annotation".to_string()));
    }

    #[test]
    fn suppresses_inline_annotation_on_prev_line() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("src/config.rs", "AKIA...MPLE", "aws_access_key");
        let prev = "// zentra:ignore";
        assert_eq!(v.check(&m, r#"api_key = "AKIAIOSFODNN7EXAMPLE""#, Some(prev)),
            Some("inline_annotation".to_string()));
    }

    #[test]
    fn suppresses_variable_name_reference() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("src/config.rs", "api_key_var", "env_api_key");
        assert_eq!(v.check(&m, "", None), Some("variable_name_only".to_string()));
    }

    #[test]
    fn does_not_suppress_real_secret() {
        let al = no_allowlist();
        let v = ContextValidator::new(&al);
        let m = make_match("src/config.rs", "AKIA...MPLE", "aws_access_key");
        assert_eq!(v.check(&m, r#"key = "AKIAIOSFODNN7EXAMPLE""#, None), None);
    }
}
