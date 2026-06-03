use zentra_cli::provider::cli::{serialize_messages, CliKind};
use zentra_cli::provider::AgentMessage;

#[test]
fn serialize_user_message() {
    let msgs = vec![AgentMessage::User("scan this".to_string())];
    let out = serialize_messages(&msgs);
    assert!(out.contains("Human: scan this"));
}

#[test]
fn serialize_tool_result_wraps_content_in_cdata() {
    let msgs = vec![
        AgentMessage::User("go".to_string()),
        AgentMessage::Assistant {
            content: "calling tool".to_string(),
            tool_calls: vec![],
        },
        AgentMessage::ToolResult {
            id: "tc1".to_string(),
            name: "read_file".to_string(),
            content: "fn main() {}".to_string(),
        },
    ];
    let out = serialize_messages(&msgs);
    assert!(out.contains("<ztool_result id=\"tc1\" name=\"read_file\"><![CDATA[fn main() {}]]></ztool_result>"));
}

#[test]
fn serialize_tool_result_escapes_cdata_end_sequence() {
    let msgs = vec![
        AgentMessage::User("go".to_string()),
        AgentMessage::Assistant { content: String::new(), tool_calls: vec![] },
        AgentMessage::ToolResult {
            id: "tc2".to_string(),
            name: "read_file".to_string(),
            content: "a]]>b".to_string(),
        },
    ];
    let out = serialize_messages(&msgs);
    assert!(out.contains("a]]]]><![CDATA[>b"));
}
