// tests/agent_test.rs
use zentra_cli::{agent, state, tools};

#[test]
fn modules_exist() {
    // compile-time verification that all new modules are declared
    let _ = std::any::type_name::<agent::ScannerType>();
    let _ = std::any::type_name::<state::Finding>();
    let _ = std::any::type_name::<tools::ToolRegistry>();
}
