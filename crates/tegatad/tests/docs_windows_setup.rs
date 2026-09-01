//! Acceptance test for the Windows setup documentation.
//!
//! The documentation is part of the contract: a second daemon instance is
//! only usable if the keys and commands that make it possible are written
//! down where an operator will look for them.

use std::path::Path;

fn setup_windows_wsl() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/setup-windows-wsl.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Given: `docs/setup-windows-wsl.md`
/// When: it is searched for the second-instance vocabulary
/// Then: `service_name`, the `Running a second instance` section, and
///       `service uninstall [--name <name>]` are all present
#[test]
fn windows_setup_documents_a_second_instance() {
    let docs = setup_windows_wsl();
    for needle in [
        "service_name",
        "Running a second instance",
        "service uninstall [--name <name>]",
    ] {
        assert!(
            docs.contains(needle),
            "docs/setup-windows-wsl.md lacks {needle:?}"
        );
    }
}
