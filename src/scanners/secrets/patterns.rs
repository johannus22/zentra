use regex::Regex;
use std::sync::OnceLock;

pub struct DetectorPattern {
    pub name: &'static str,
    pub re: Regex,
    pub secret_group: usize,
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub detector: String,
    pub secret: String,
    pub redacted: String,
}

pub fn redact(s: &str) -> String {
    let s = s.trim_matches(|c| c == '\'' || c == '"');
    if s.len() <= 8 {
        return format!("{}...", &s[..s.len().min(2)]);
    }
    format!("{}...{}", &s[..4], &s[s.len() - 4..])
}

pub fn all_patterns() -> &'static [DetectorPattern] {
    static PATTERNS: OnceLock<Vec<DetectorPattern>> = OnceLock::new();
    PATTERNS.get_or_init(build_patterns)
}

pub fn scan_line(line: &str, patterns: &[DetectorPattern]) -> Vec<PatternMatch> {
    let mut results = Vec::new();
    for p in patterns {
        for caps in p.re.captures_iter(line) {
            if let Some(secret) = caps.get(p.secret_group) {
                let s = secret.as_str();
                results.push(PatternMatch {
                    detector: p.name.to_string(),
                    secret: s.to_string(),
                    redacted: redact(s),
                });
            }
        }
    }
    results
}

fn det(name: &'static str, pattern: &str) -> DetectorPattern {
    DetectorPattern {
        name,
        re: Regex::new(pattern).unwrap_or_else(|e| panic!("invalid pattern '{}': {}", name, e)),
        secret_group: 1,
    }
}

fn build_patterns() -> Vec<DetectorPattern> {
    vec![
        // AWS
        det("aws_access_key", r"(AKIA[0-9A-Z]{16})"),
        det("aws_session_token", r"(ASIA[0-9A-Z]{16})"),
        det("aws_secret_key", r#"(?i)aws.{0,20}(?:secret|key).{0,20}['"\s]([0-9a-zA-Z/+]{40})['"\s]"#),
        // GitHub
        det("github_pat", r"(ghp_[a-zA-Z0-9]{36})"),
        det("github_fine_grained", r"(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})"),
        det("github_app_token", r"(ghs_[a-zA-Z0-9]{36})"),
        det("github_oauth", r"(gho_[a-zA-Z0-9]{36})"),
        // GitLab
        det("gitlab_pat", r"(glpat-[a-zA-Z0-9-]{20})"),
        det("gitlab_project_token", r"(glprt-[a-zA-Z0-9-]{20})"),
        det("gitlab_deploy_token", r"(gldt-[a-zA-Z0-9-]{20})"),
        // Stripe
        det("stripe_secret_live", r"(sk_live_[a-zA-Z0-9]{24,99})"),
        det("stripe_secret_test", r"(sk_test_[a-zA-Z0-9]{24,99})"),
        det("stripe_restricted", r"(rk_live_[a-zA-Z0-9]{24,99})"),
        // Twilio
        det("twilio_account_sid", r"(AC[a-f0-9]{32})"),
        // Slack
        det("slack_token", r"(xox[baprs]-[a-zA-Z0-9-]{10,99})"),
        det("slack_webhook", r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)"),
        // JWT
        det("jwt", r"(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)"),
        // Private keys
        det("private_key_header", r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
        // .env literals (value is group 1 via non-capturing prefix)
        det("env_password", r#"(?i)(?:^|[\s;])(?:PASSWORD|PASSWD|PWD)\s*=\s*['"]?([a-zA-Z0-9/+_.!@#$%^&*-]{8,})['"]?"#),
        det("env_api_key", r#"(?i)(?:^|[\s;])(?:API_KEY|APIKEY)\s*=\s*['"]?([a-zA-Z0-9/+_.,-]{16,})['"]?"#),
        det("env_secret", r#"(?i)(?:^|[\s;])(?:SECRET|SECRET_KEY)\s*=\s*['"]?([a-zA-Z0-9/+_.,-]{16,})['"]?"#),
        det("env_token", r#"(?i)(?:^|[\s;])(?:AUTH_TOKEN|ACCESS_TOKEN)\s*=\s*['"]?([a-zA-Z0-9/+_.,-]{16,})['"]?"#),
        // Connection strings (password is group 1)
        det("postgres_url", r"postgres(?:ql)?://[^:]+:([^@\s]{8,})@"),
        det("mysql_url", r"mysql://[^:]+:([^@\s]{8,})@"),
        det("mongodb_url", r"mongodb(?:\+srv)?://[^:]+:([^@\s]{8,})@"),
        // GCP
        det("gcp_api_key", r"(\bAIza[0-9A-Za-z_-]{35}\b)"),
        // Azure
        det("azure_storage_key", r"(?i)AccountKey=([a-zA-Z0-9+/]{88}=*)"),
        // Email/notifications
        det("sendgrid_key", r"(SG\.[a-zA-Z0-9_.,-]{22}\.[a-zA-Z0-9_.,-]{43})"),
        det("mailchimp_key", r"([a-f0-9]{32}-us[0-9]{1,2})"),
        // LLM providers
        det("anthropic_key", r"(sk-ant-[a-zA-Z0-9-]{93,})"),
        det("openai_key", r"(sk-[a-zA-Z0-9T]{48,})"),
        det("huggingface_token", r"(hf_[a-zA-Z0-9]{34,})"),
        // Package registries
        det("npm_token", r"(npm_[a-zA-Z0-9]{36})"),
        // Chat/social
        det("discord_token", r"([MNO][a-zA-Z0-9_-]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27})"),
        det("slack_signing_secret", r#"(?i)signing.?secret['"\s:=]+([a-f0-9]{32})"#),
        // Payments
        det("square_access_token", r"(sq0atp-[a-zA-Z0-9_-]{22})"),
        det("square_client_secret", r"(sq0csp-[a-zA-Z0-9_-]{43})"),
        // Cloud providers
        det("digitalocean_pat", r"(dop_v1_[a-zA-Z0-9]{64})"),
        det("shopify_secret", r"(shpss_[a-fA-F0-9]{32})"),
        // Generic credential assignments
        det("generic_secret_assign", r#"(?i)(?:secret|password|passwd|token|api_?key|auth|credential)\s*[:=]\s*['"]([a-zA-Z0-9/+_.!@#$%^&*-]{12,})['"]"#),
        // HTTP basic auth in URLs
        det("http_basic_auth", r"https?://[^:@\s]+:([^@\s]{8,})@[^\s]+"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_access_key() {
        let patterns = all_patterns();
        let hits = scan_line("export AWS_KEY=AKIAIOSFODNN7EXAMPLE", patterns);
        assert!(hits.iter().any(|h| h.detector == "aws_access_key"), "expected aws_access_key hit");
    }

    #[test]
    fn detects_github_pat() {
        let patterns = all_patterns();
        let hits = scan_line("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", patterns);
        assert!(hits.iter().any(|h| h.detector == "github_pat"), "expected github_pat hit");
    }

    #[test]
    fn detects_stripe_live_key() {
        let patterns = all_patterns();
        let hits = scan_line("STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx", patterns);
        assert!(hits.iter().any(|h| h.detector == "stripe_secret_live"), "expected stripe_secret_live hit");
    }

    #[test]
    fn detects_postgres_password() {
        let patterns = all_patterns();
        let hits = scan_line("postgres://user:s3cr3tpassword@localhost/db", patterns);
        assert!(hits.iter().any(|h| h.detector == "postgres_url"), "expected postgres_url hit");
    }

    #[test]
    fn redact_shows_first_and_last_four() {
        let patterns = all_patterns();
        let hits = scan_line("AKIAIOSFODNN7EXAMPLE", patterns);
        let hit = hits.iter().find(|h| h.detector == "aws_access_key").unwrap();
        assert!(hit.redacted.starts_with("AKIA"), "expected first 4 chars");
        assert!(hit.redacted.ends_with("MPLE"), "expected last 4 chars");
        assert!(hit.redacted.contains("..."), "expected ellipsis");
    }

    #[test]
    fn redact_short_secret_is_truncated() {
        assert_eq!(redact("abcdef"), "ab...");
    }

    #[test]
    fn no_false_positive_on_normal_word() {
        let patterns = all_patterns();
        let hits = scan_line("let name = \"hello_world\";", patterns);
        assert!(hits.is_empty() || hits.iter().all(|h| h.secret.len() < 8));
    }
}
