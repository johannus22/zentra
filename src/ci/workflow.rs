use std::path::Path;

use anyhow::{bail, Result};

use super::CiPlatformKind;

pub fn generate_ci_workflow_at(root: &Path, platform: CiPlatformKind) -> Result<()> {
    match platform {
        CiPlatformKind::Github => write_github_workflow(root),
        CiPlatformKind::Gitlab => write_gitlab_workflow(root),
    }
}

fn write_github_workflow(root: &Path) -> Result<()> {
    let dir = root.join(".github").join("workflows");
    let path = dir.join("zentra.yml");
    if path.exists() {
        bail!(
            ".github/workflows/zentra.yml already exists; not overwriting existing GitHub workflow"
        );
    }
    std::fs::create_dir_all(&dir)?;
    std::fs::write(path, GITHUB_WORKFLOW)?;
    Ok(())
}

fn write_gitlab_workflow(root: &Path) -> Result<()> {
    let path = root.join(".gitlab-ci.yml");
    if path.exists() {
        bail!(".gitlab-ci.yml already exists; not overwriting existing GitLab CI config");
    }
    std::fs::write(path, GITLAB_WORKFLOW)?;
    Ok(())
}

const GITHUB_WORKFLOW: &str = r#"name: Zentra Security

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  zentra-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run Zentra CI
        run: zentra ci
      - name: Upload Zentra CI report
        uses: actions/upload-artifact@v4
        with:
          name: zentra-ci-report
          path: |
            .zentra/ci-report.md
            .zentra/ci-report.json
"#;

const GITLAB_WORKFLOW: &str = r#"zentra_security_scan:
  stage: test
  variables:
    GIT_DEPTH: "0"
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  script:
    - zentra ci
  artifacts:
    when: always
    paths:
      - .zentra/ci-report.md
      - .zentra/ci-report.json
"#;
