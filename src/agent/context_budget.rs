use crate::provider::{AgentMessage, ToolDefinition};

/// Conservative chars-per-token ratio for estimation across mixed models.
const CHARS_PER_TOKEN: usize = 4;
/// Percent of the usable window input may occupy (margin for heuristic error).
const BUDGET_FRACTION_PCT: usize = 85;
/// Deterministic marker prefixing a compacted (stubbed) tool result.
const ELISION_MARKER: &str = "[elided]";
/// Maximum chars a single tool result may occupy in the message history.
/// Larger results are truncated with a notice before they enter the history.
pub const MAX_TOOL_RESULT_CHARS: usize = 20_000;
/// Chars preserved from the head of a compacted tool result.
const COMPACT_HEAD_CHARS: usize = 500;
/// Chars preserved from the tail of a compacted tool result.
const COMPACT_TAIL_CHARS: usize = 500;

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

/// Truncate a tool result to `MAX_TOOL_RESULT_CHARS`. If the content exceeds
/// the limit, append a notice with the original char count. No-op for content
/// under the limit. Call this at dispatch time, before the result enters the
/// message history, so one large `read_file` or `grep_code` cannot eat the
/// whole budget.
pub fn bound_tool_result(content: &str) -> String {
    if content.chars().count() <= MAX_TOOL_RESULT_CHARS {
        return content.to_string();
    }
    let total = content.chars().count();
    let truncated: String = content.chars().take(MAX_TOOL_RESULT_CHARS).collect();
    format!(
        "{truncated}\n\n[... output truncated: original was {total} chars, showing first {MAX_TOOL_RESULT_CHARS} ...]"
    )
}

/// Compact a tool result into a short summary. The result keeps the head and
/// tail excerpts when the content is long enough to be worth excerpting, or
/// elides short content entirely. The output always starts with
/// `ELISION_MARKER`, so a second compaction pass on the same content is a
/// no-op (the main loop skips results already prefixed with the marker).
fn compact_content(name: &str, content: &str) -> String {
    let total = content.chars().count();
    if total <= COMPACT_HEAD_CHARS + COMPACT_TAIL_CHARS {
        // Too short to meaningfully compact. Elide entirely.
        return format!(
            "{ELISION_MARKER} {name} result ({total} chars) removed to fit context. Re-run the tool if you need it again."
        );
    }
    let head: String = content.chars().take(COMPACT_HEAD_CHARS).collect();
    let tail: String = content.chars().skip(total - COMPACT_TAIL_CHARS).collect();
    format!(
        "{ELISION_MARKER} {name} result (originally {total} chars). Excerpt:\n--- head ---\n{head}\n--- tail ---\n{tail}\n--- end excerpt ---\nRe-run the tool for full content."
    )
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
                let compacted = compact_content(name, content);
                *content = compacted;
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
        // Three ~4000-char results (~1000 tokens each). The compacted form
        // keeps ~1150 chars (head + tail excerpts), so a 2000-token budget
        // forces stubbing the two oldest while leaving the newest verbatim.
        let mut msgs = vec![
            tr("list_files", &"a".repeat(4000)),
            tr("grep_code", &"b".repeat(4000)),
            tr("read_file", &"c".repeat(4000)),
        ];
        let outcome = compact_to_budget(&mut msgs, "", &[], 2000);
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

    #[test]
    fn bound_tool_result_is_noop_under_limit() {
        let content = "x".repeat(MAX_TOOL_RESULT_CHARS);
        let bounded = bound_tool_result(&content);
        assert_eq!(bounded, content);
    }

    #[test]
    fn bound_tool_result_truncates_over_limit() {
        // One char over the limit triggers truncation.
        let original = "y".repeat(MAX_TOOL_RESULT_CHARS + 1000);
        let bounded = bound_tool_result(&original);
        assert!(bounded.len() < original.len());
        // Truncated body is exactly MAX_TOOL_RESULT_CHARS of the original,
        // followed by the two-newline separator and the notice.
        let body: String = original.chars().take(MAX_TOOL_RESULT_CHARS).collect();
        assert!(bounded.starts_with(&body));
        assert!(bounded.contains("output truncated"));
        assert!(bounded.contains(&format!("original was {} chars", MAX_TOOL_RESULT_CHARS + 1000)));
        assert!(bounded.contains(&format!("showing first {MAX_TOOL_RESULT_CHARS}")));
    }

    #[test]
    fn bound_tool_result_handles_empty_string() {
        assert_eq!(bound_tool_result(""), "");
    }

    #[test]
    fn compact_content_short_elides_entirely() {
        // Below COMPACT_HEAD_CHARS + COMPACT_TAIL_CHARS (1000). Full elision.
        let short = "abc".repeat(10); // 30 chars
        let compacted = compact_content("read_file", &short);
        assert!(compacted.starts_with(ELISION_MARKER));
        assert!(compacted.contains("30 chars"));
        // No excerpt markers for short content.
        assert!(!compacted.contains("--- head ---"));
        assert!(!compacted.contains("--- tail ---"));
    }

    #[test]
    fn compact_content_long_includes_head_and_tail() {
        // 2000 chars: well above the 1000-char excerpt threshold.
        let mut payload = String::new();
        payload.push_str("HEADMARK");
        payload.push_str(&"a".repeat(492)); // 500 chars total head sentinel region
        payload.push_str(&"m".repeat(1000)); // middle that should be dropped
        payload.push_str(&"b".repeat(492));
        payload.push_str("TAILMARK"); // 500 chars total tail sentinel region; total 2000
        assert_eq!(payload.chars().count(), 2000);

        let compacted = compact_content("read_file", &payload);
        assert!(compacted.starts_with(ELISION_MARKER));
        assert!(compacted.contains("originally 2000 chars"));
        assert!(compacted.contains("--- head ---"));
        assert!(compacted.contains("--- tail ---"));
        // Head excerpt includes the head sentinel.
        assert!(compacted.contains("HEADMARK"));
        // Tail excerpt includes the tail sentinel.
        assert!(compacted.contains("TAILMARK"));
        // The dropped middle must not appear.
        assert!(!compacted.contains('m'));
    }

    #[test]
    fn compact_content_result_starts_with_elision_marker() {
        // Both branches (short and long) must prefix ELISION_MARKER so the
        // main loop's `!content.starts_with(ELISION_MARKER)` check treats an
        // already-compacted result as not eligible for re-compaction.
        let short = compact_content("grep_code", "tiny");
        let long = compact_content("grep_code", &"z".repeat(2000));
        assert!(short.starts_with(ELISION_MARKER));
        assert!(long.starts_with(ELISION_MARKER));
    }
}
