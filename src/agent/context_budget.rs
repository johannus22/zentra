use crate::provider::{AgentMessage, ToolDefinition};

/// Conservative chars-per-token ratio for estimation across mixed models.
const CHARS_PER_TOKEN: usize = 4;
/// Percent of the usable window input may occupy (margin for heuristic error).
const BUDGET_FRACTION_PCT: usize = 85;
/// Deterministic marker prefixing a compacted (stubbed) tool result.
const ELISION_MARKER: &str = "[elided]";

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Fit { stubbed: usize },
    Irreducible { estimate: usize, budget: usize },
}

fn message_chars(m: &AgentMessage) -> usize {
    match m {
        AgentMessage::User(s) => s.len(),
        AgentMessage::Assistant { content, tool_calls } => {
            content.len()
                + tool_calls
                    .iter()
                    .map(|tc| tc.name.len() + tc.arguments.to_string().len())
                    .sum::<usize>()
        }
        AgentMessage::ToolResult { name, content, .. } => name.len() + content.len(),
    }
}

/// Estimate input tokens for a request: system + all message text + tool
/// definitions, summed chars / CHARS_PER_TOKEN (rounded up).
pub fn estimate_tokens(system: &str, messages: &[AgentMessage], tools: &[ToolDefinition]) -> usize {
    let mut chars = system.len();
    for m in messages {
        chars += message_chars(m);
    }
    for t in tools {
        chars += t.name.len() + t.description.len() + t.parameters.to_string().len();
    }
    chars.div_ceil(CHARS_PER_TOKEN)
}

/// Max input tokens allowed: (context_window - max_output) * BUDGET_FRACTION_PCT%.
pub fn input_budget(context_window: u32, max_output: u32) -> usize {
    let usable = context_window.saturating_sub(max_output) as usize;
    usable * BUDGET_FRACTION_PCT / 100
}

/// While the estimate exceeds `budget` and a not-yet-stubbed ToolResult exists,
/// stub the OLDEST one (deterministic marker + original char count) and
/// re-estimate. Returns Fit with the number stubbed this call, or Irreducible
/// when nothing more can be stubbed and it is still over budget.
pub fn compact_to_budget(
    messages: &mut [AgentMessage],
    system: &str,
    tools: &[ToolDefinition],
    budget: usize,
) -> Outcome {
    let mut stubbed = 0;
    loop {
        if estimate_tokens(system, messages, tools) <= budget {
            return Outcome::Fit { stubbed };
        }
        let target = messages.iter_mut().find(|m| {
            matches!(m, AgentMessage::ToolResult { content, .. } if !content.starts_with(ELISION_MARKER))
        });
        match target {
            Some(AgentMessage::ToolResult { name, content, .. }) => {
                // Replacing the content discards any prompt-injection wrapper around the
                // original tool result. This is safe: injection scanning happens at
                // append time (in the scanner loop), not at send time, so no injection
                // signal is lost by stubbing here.
                *content = format!(
                    "{ELISION_MARKER} {name} result ({} chars) removed to fit context — re-run the tool if you need it again.",
                    content.len()
                );
                stubbed += 1;
            }
            _ => {
                return Outcome::Irreducible {
                    estimate: estimate_tokens(system, messages, tools),
                    budget,
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{AgentMessage, ToolCall};

    fn tr(name: &str, content: &str) -> AgentMessage {
        AgentMessage::ToolResult {
            id: "id".to_string(),
            name: name.to_string(),
            content: content.to_string(),
        }
    }

    #[test]
    fn estimate_grows_with_content() {
        let small = vec![AgentMessage::User("hi".to_string())];
        let big = vec![AgentMessage::User("x".repeat(4000))];
        assert!(estimate_tokens("", &big, &[]) > estimate_tokens("", &small, &[]));
    }

    #[test]
    fn input_budget_reserves_output_and_margin() {
        // (100_000 - 4_096) * 85 / 100 = 81_518
        assert_eq!(input_budget(100_000, 4096), 81_518);
        // saturating: output >= window -> 0
        assert_eq!(input_budget(1000, 4096), 0);
    }

    #[test]
    fn compacts_oldest_first_until_fit() {
        // Three ~4000-char results (~1000 tokens each). Budget 1500 tokens
        // forces stubbing the two oldest, leaving the newest verbatim.
        let mut msgs = vec![
            tr("list_files", &"a".repeat(4000)),
            tr("grep_code", &"b".repeat(4000)),
            tr("read_file", &"c".repeat(4000)),
        ];
        let outcome = compact_to_budget(&mut msgs, "", &[], 1500);
        assert!(matches!(outcome, Outcome::Fit { stubbed } if stubbed == 2));
        assert!(matches!(&msgs[0], AgentMessage::ToolResult { content, .. } if content.starts_with("[elided]")));
        assert!(matches!(&msgs[1], AgentMessage::ToolResult { content, .. } if content.starts_with("[elided]")));
        assert!(matches!(&msgs[2], AgentMessage::ToolResult { content, .. } if content == &"c".repeat(4000)));
    }

    #[test]
    fn noop_when_already_under_budget() {
        let mut msgs = vec![tr("read_file", "small")];
        let outcome = compact_to_budget(&mut msgs, "", &[], 1_000_000);
        assert!(matches!(outcome, Outcome::Fit { stubbed: 0 }));
        assert!(matches!(&msgs[0], AgentMessage::ToolResult { content, .. } if content == "small"));
    }

    #[test]
    fn irreducible_when_system_alone_exceeds_budget() {
        // No tool results to stub and the system prompt alone is over budget.
        let mut msgs = vec![AgentMessage::Assistant {
            content: String::new(),
            tool_calls: vec![ToolCall { id: "1".into(), name: "x".into(), arguments: serde_json::json!({}) }],
        }];
        let outcome = compact_to_budget(&mut msgs, &"s".repeat(8000), &[], 100);
        assert!(matches!(outcome, Outcome::Irreducible { .. }));
    }

    #[test]
    fn already_stubbed_results_are_not_recompacted() {
        let mut msgs = vec![tr("list_files", &"a".repeat(4000)), tr("read_file", &"b".repeat(4000))];
        // First pass stubs the oldest.
        let first = compact_to_budget(&mut msgs, "", &[], 1100);
        let after_first: Vec<String> = msgs.iter().map(|m| match m {
            AgentMessage::ToolResult { content, .. } => content.clone(),
            _ => String::new(),
        }).collect();
        // Second pass at the same budget must not change anything.
        let second = compact_to_budget(&mut msgs, "", &[], 1100);
        let after_second: Vec<String> = msgs.iter().map(|m| match m {
            AgentMessage::ToolResult { content, .. } => content.clone(),
            _ => String::new(),
        }).collect();
        assert!(matches!(first, Outcome::Fit { .. }));
        assert!(matches!(second, Outcome::Fit { stubbed: 0 }));
        assert_eq!(after_first, after_second);
    }
}
