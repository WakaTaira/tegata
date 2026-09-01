//! Acceptance tests for the Windows service command line.
//!
//! One test per acceptance condition of the private brief. These drive the
//! built `tegatad.exe` and therefore only compile on Windows, where the CI
//! job runs them without elevation: nothing here creates a service.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

fn tegatad() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tegatad"))
}

/// A directory under the user's temporary directory, which is never
/// directly under `%ProgramData%`.
fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tegata-gauntlet-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

/// Given: the `service uninstall` command
/// When: its help is printed
/// Then: it documents `--name` with the default `tegatad`
#[test]
fn service_uninstall_documents_the_name_option_with_the_default() {
    let output = tegatad()
        .args(["service", "uninstall", "--help"])
        .output()
        .expect("run tegatad service uninstall --help");
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "help exits successfully: {help}");
    assert!(help.contains("--name"), "help lists --name: {help}");
    assert!(
        help.contains("[default: tegatad]"),
        "help states the default service name: {help}"
    );
}

/// Given: a valid configuration stored outside `%ProgramData%`
/// When: `service install --config` is run with it
/// Then: it fails before touching the service manager, naming `%ProgramData%`,
///       and no service of the configured name exists afterwards
#[test]
fn service_install_refuses_a_configuration_outside_program_data() {
    let dir = scratch_dir("install");
    let service_name = format!("tegatad-gauntlet-{}", std::process::id());
    let config_path = dir.join("config.toml");
    let state_dir = dir.join("state");
    std::fs::write(
        &config_path,
        format!(
            r#"
state_dir = {state_dir:?}
audit_log_path = {audit:?}
service_name = "{service_name}"
pipe_name = "{service_name}"
tcp_port = 0
"#,
            state_dir = state_dir.to_string_lossy(),
            audit = state_dir.join("audit.log").to_string_lossy(),
        ),
    )
    .expect("write scratch configuration");

    let output = tegatad()
        .args(["service", "install", "--config"])
        .arg(&config_path)
        .output()
        .expect("run tegatad service install");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "install must fail: {stderr}");
    assert!(
        stderr.contains("%ProgramData%"),
        "the refusal names %ProgramData%: {stderr}"
    );

    let query = Command::new("sc.exe")
        .args(["query", &service_name])
        .output()
        .expect("run sc.exe query");
    assert!(
        !query.status.success(),
        "no service was created: {}",
        String::from_utf8_lossy(&query.stdout)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
