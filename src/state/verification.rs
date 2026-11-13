//! Evidence contracts. The model proposes records; the runtime validates and owns
//! review identities, source hashes, lifecycle status, and publication.

use crate::state::{Finding, Severity};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Citation {
    pub path: String,
    pub line: usize,
    pub quote: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryEvidence {
    pub principal: String,
    pub input: String,
    pub boundary: String,
    pub resource: String,
    pub impact: String,
    pub controls_reviewed: String,
    /// Ordered source path from entrypoint to boundary effect. Each citation
    /// must have been read in this review conversation.
    pub trace: Vec<Citation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case", deny_unknown_fields)]
pub enum Verdict {
    SourceVerified {
        evidence: BoundaryEvidence,
        severity: Severity,
        rationale: String,
        recommendation: String,
    },
    NeedsValidation {
        evidence: BoundaryEvidence,
        blockers: Vec<String>,
        next_step: String,
    },
    Rejected {
        reason: String,
        trace: Vec<Citation>,
    },
}

fn text(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 4096,
        "empty or oversized evidence field"
    );
    Ok(())
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SourceVerified { .. } => "source_verified",
            Self::NeedsValidation { .. } => "needs_validation",
            Self::Rejected { .. } => "rejected",
        }
    }

    pub fn trace(&self) -> &[Citation] {
        match self {
            Self::SourceVerified { evidence, .. } | Self::NeedsValidation { evidence, .. } => {
                &evidence.trace
            }
            Self::Rejected { trace, .. } => trace,
        }
    }

    pub fn explanation(&self) -> String {
        match self {
            Self::SourceVerified { rationale, .. } => rationale.clone(),
            Self::NeedsValidation {
                blockers,
                next_step,
                ..
            } => format!("{} Next: {next_step}", blockers.join("; ")),
            Self::Rejected { reason, .. } => reason.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=8).contains(&self.trace().len()),
            "require 1–8 source citations"
        );
        for citation in self.trace() {
            text(&citation.path)?;
            text(&citation.quote)?;
            ensure!(
                citation.line > 0 && citation.quote.lines().count() <= 20,
                "invalid citation range"
            );
        }
        match self {
            Self::SourceVerified {
                evidence,
                rationale,
                recommendation,
                ..
            } => {
                evidence.validate()?;
                text(rationale)?;
                text(recommendation)?;
            }
            Self::NeedsValidation {
                evidence,
                blockers,
                next_step,
            } => {
                evidence.validate()?;
                ensure!(
                    (1..=8).contains(&blockers.len()),
                    "require exact unresolved blockers"
                );
                for blocker in blockers {
                    text(blocker)?;
                }
                text(next_step)?;
            }
            Self::Rejected { reason, .. } => text(reason)?,
        }
        Ok(())
    }
}

impl BoundaryEvidence {
    fn validate(&self) -> Result<()> {
        for value in [
            &self.principal,
            &self.input,
            &self.boundary,
            &self.resource,
            &self.impact,
            &self.controls_reviewed,
        ] {
            text(value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedRecord {
    pub fingerprint: String,
    /// Discovery severity is a proposal, not a finalized severity.
    pub candidate: Finding,
    pub verdict: Option<Verdict>,
    pub reviewer: Option<String>,
    pub final_reviewer: Option<String>,
    pub source_hashes: std::collections::BTreeMap<String, String>,
    pub incomplete_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRun {
    pub schema_version: u8,
    pub run_id: String,
    pub status: String,
    pub records: Vec<VerifiedRecord>,
}

impl VerificationRun {
    pub fn complete(&self) -> bool {
        self.records.iter().all(|record| {
            record.incomplete_reason.is_none()
                && record.verdict.is_some()
                && record.reviewer.is_some()
                && record.final_reviewer.is_some()
                && record.reviewer != record.final_reviewer
        })
    }

    /// Project records into the backward-compatible candidate file. Only the
    /// runtime can mint SourceVerified; legacy Confirmed is not a CI credential.
    pub fn findings(&self) -> Vec<Finding> {
        use crate::state::finding::Screening;
        self.records.iter().map(|record| {
            let mut finding = record.candidate.clone();
            finding.confidence = None;
            finding.cvss_vector = None;
            finding.cvss_score = None;
            finding.screening = Some(Screening::Incomplete);
            finding.evidence = record.incomplete_reason.clone();
            if record.incomplete_reason.is_none() {
                if let Some(verdict) = &record.verdict {
                    finding.evidence = Some(verdict.explanation());
                    finding.screening = Some(match verdict {
                        Verdict::SourceVerified { evidence, severity, recommendation, .. } => {
                            finding.severity = *severity;
                            finding.description = format!("{} crosses {} through {}. Affected resource: {}. Source-supported impact: {}", evidence.principal, evidence.boundary, evidence.input, evidence.resource, evidence.impact);
                            finding.location = evidence.trace.first().map(|c| format!("{}:{}", c.path, c.line));
                            finding.recommendation = recommendation.clone();
                            Screening::SourceVerified
                        }
                        Verdict::NeedsValidation { .. } => Screening::NeedsValidation,
                        Verdict::Rejected { .. } => Screening::Rejected,
                    });
                }
            }
            finding
        }).collect()
    }

    pub fn markdown(&self) -> String {
        let mut out = format!("# Zentra Verification Report\n\nRun: {}\n\nStatus: **{}**\n\nSource verification is not runtime reproduction. Coverage is reported separately in `coverage.md`.\n", self.run_id, self.status);
        for label in [
            "source_verified",
            "needs_validation",
            "rejected",
            "incomplete",
        ] {
            out.push_str(&format!("\n## {label}\n\n"));
            let mut count = 0;
            for record in &self.records {
                let actual = if record.incomplete_reason.is_some() {
                    "incomplete"
                } else {
                    record
                        .verdict
                        .as_ref()
                        .map(Verdict::label)
                        .unwrap_or("incomplete")
                };
                if actual != label {
                    continue;
                }
                count += 1;
                // Escape Markdown control text so candidate content cannot forge
                // report sections. JSON is the authoritative structured artifact.
                out.push_str(&format!(
                    "### {}\n\nFingerprint: `{}`\n\n",
                    plain(&record.candidate.title),
                    record.fingerprint
                ));
                if let Some(reason) = &record.incomplete_reason {
                    out.push_str(&format!("{}\n\n", plain(reason)));
                } else if let Some(verdict) = &record.verdict {
                    if let Verdict::SourceVerified {
                        severity,
                        evidence,
                        recommendation,
                        ..
                    } = verdict
                    {
                        out.push_str(&format!(
                            "Severity: {severity}\n\nImpact: {}\n\nFix: {}\n\n",
                            plain(&evidence.impact),
                            plain(recommendation)
                        ));
                    }
                    out.push_str(&format!("{}\n\n", plain(&verdict.explanation())));
                    for citation in verdict.trace() {
                        out.push_str(&format!(
                            "- {}:{} — {}\n",
                            plain(&citation.path),
                            citation.line,
                            plain(&citation.quote)
                        ));
                    }
                    out.push('\n');
                }
            }
            if count == 0 {
                out.push_str("None recorded.\n");
            }
        }
        out
    }
}

fn plain(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\n' | '\r' => " ".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '*' | '_' | '#' | '[' | ']' | '`' | '\\' => vec!['\\', ch],
            _ => vec![ch],
        })
        .collect()
}
