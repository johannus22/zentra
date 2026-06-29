//! CVSS v3.1 base-score calculator. Pure arithmetic, no I/O. Base metrics only
//! (temporal/environmental metrics, if present in the vector, are ignored).

/// Qualitative severity rating for a CVSS base score (v3.1 bands).
pub fn rating(score: f32) -> &'static str {
    if score <= 0.0 {
        "None"
    } else if score < 4.0 {
        "Low"
    } else if score < 7.0 {
        "Medium"
    } else if score < 9.0 {
        "High"
    } else {
        "Critical"
    }
}

/// Compute the CVSS v3.1 base score + rating from a base vector string.
/// Returns `None` if the prefix isn't `CVSS:3.1/`, a required base metric is
/// missing, or any metric value is invalid.
pub fn compute_base_score(vector: &str) -> Option<(f32, &'static str)> {
    let body = vector.strip_prefix("CVSS:3.1/")?;

    let mut av = None;
    let mut ac = None;
    let mut pr_raw = None;
    let mut ui = None;
    let mut scope_changed = None;
    let mut c = None;
    let mut i = None;
    let mut a = None;

    for part in body.split('/') {
        let (k, v) = part.split_once(':')?;
        match k {
            "AV" => {
                av = Some(match v {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.2,
                    _ => return None,
                })
            }
            "AC" => {
                ac = Some(match v {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return None,
                })
            }
            "PR" => pr_raw = Some(v.to_string()),
            "UI" => {
                ui = Some(match v {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return None,
                })
            }
            "S" => {
                scope_changed = Some(match v {
                    "U" => false,
                    "C" => true,
                    _ => return None,
                })
            }
            "C" => {
                c = Some(match v {
                    "H" => 0.56,
                    "L" => 0.22,
                    "N" => 0.0,
                    _ => return None,
                })
            }
            "I" => {
                i = Some(match v {
                    "H" => 0.56,
                    "L" => 0.22,
                    "N" => 0.0,
                    _ => return None,
                })
            }
            "A" => {
                a = Some(match v {
                    "H" => 0.56,
                    "L" => 0.22,
                    "N" => 0.0,
                    _ => return None,
                })
            }
            _ => {} // ignore unknown / temporal / environmental metrics
        }
    }

    let av: f64 = av?;
    let ac: f64 = ac?;
    let ui: f64 = ui?;
    let scope_changed = scope_changed?;
    let c: f64 = c?;
    let i: f64 = i?;
    let a: f64 = a?;

    // Privileges Required value depends on Scope.
    let pr: f64 = match (pr_raw?.as_str(), scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };

    if impact <= 0.0 {
        return Some((0.0, rating(0.0)));
    }

    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };

    let score = roundup(raw);
    Some((score, rating(score)))
}

/// CVSS v3.1 "Roundup": the smallest number to one decimal place that is >= input.
fn roundup(input: f64) -> f32 {
    let int_input = (input * 100_000.0).round() as i64;
    let score = if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input as f64 / 10_000.0).floor() + 1.0) / 10.0
    };
    score as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score_of(v: &str) -> f32 {
        compute_base_score(v).expect("should parse").0
    }

    #[test]
    fn critical_full_impact() {
        let (s, r) = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((s - 9.8).abs() < 0.001, "got {s}");
        assert_eq!(r, "Critical");
    }

    #[test]
    fn high_conf_only() {
        assert!((score_of("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") - 7.5).abs() < 0.001);
    }

    #[test]
    fn medium_scope_changed_xss() {
        // Classic reflected-XSS vector, scope changed.
        let (s, r) = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").unwrap();
        assert!((s - 6.1).abs() < 0.001, "got {s}");
        assert_eq!(r, "Medium");
    }

    #[test]
    fn low_score() {
        let (s, r) = compute_base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N").unwrap();
        assert!((s - 3.1).abs() < 0.001, "got {s}");
        assert_eq!(r, "Low");
    }

    #[test]
    fn none_when_no_impact() {
        let (s, r) = compute_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").unwrap();
        assert_eq!(s, 0.0);
        assert_eq!(r, "None");
    }

    #[test]
    fn rejects_wrong_prefix_and_malformed() {
        assert!(compute_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_none());
        assert!(compute_base_score("not a vector").is_none());
        assert!(compute_base_score("CVSS:3.1/AV:N/AC:L").is_none()); // missing metrics
    }

    #[test]
    fn rating_bands() {
        assert_eq!(rating(0.0), "None");
        assert_eq!(rating(3.9), "Low");
        assert_eq!(rating(4.0), "Medium");
        assert_eq!(rating(7.0), "High");
        assert_eq!(rating(9.0), "Critical");
    }
}
