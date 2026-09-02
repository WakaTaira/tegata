//! Contract tests for the Windows instance naming helpers, written before
//! the implementation. (The end-to-end acceptance suite lives under
//! `tests/acceptance/`; these pin the helpers it cannot reach.)
//!
//! The helpers are pure string logic so they run on every platform, which is
//! what lets the Linux checks guard behaviour that only the Windows service
//! runtime uses.

use tegata_core::windows_instance::{
    firewall_rule_name, install_root_under, service_account, validate_service_name,
};

/// Given: the service name "tegatad-rig"
/// When: it is validated
/// Then: it is accepted
#[test]
fn service_name_with_letters_digits_and_dashes_is_accepted() {
    validate_service_name("tegatad-rig").expect("a plain service name is accepted");
}

/// Given: a service name carrying a PowerShell quote and a command separator
/// When: it is validated
/// Then: it is refused, and the message names the allowed characters
#[test]
fn service_name_with_shell_metacharacters_is_refused() {
    let error = validate_service_name("tegatad'; Remove-Item -Recurse C:\\ #")
        .expect_err("shell metacharacters are refused");
    assert!(
        error.to_string().contains("letters"),
        "error should name the allowed characters: {error}"
    );
}

/// Given: an empty service name
/// When: it is validated
/// Then: it is refused
#[test]
fn empty_service_name_is_refused() {
    validate_service_name("").expect_err("an empty service name is refused");
}

/// Given: a service name containing a path separator
/// When: it is validated
/// Then: it is refused
#[test]
fn service_name_with_a_path_separator_is_refused() {
    validate_service_name(r"tegatad\rig").expect_err("a backslash is refused");
    validate_service_name("tegatad/rig").expect_err("a slash is refused");
}

/// Given: the service name "tegatad-rig"
/// When: the virtual account and the firewall rule name are derived
/// Then: they are `NT SERVICE\tegatad-rig` and `tegatad-rig WSL TCP`
#[test]
fn service_name_derives_the_account_and_the_firewall_rule() {
    assert_eq!(service_account("tegatad-rig"), r"NT SERVICE\tegatad-rig");
    assert_eq!(firewall_rule_name("tegatad-rig"), "tegatad-rig WSL TCP");
}

/// Given: `%ProgramData%` = `C:\ProgramData` and the default configuration path
/// When: the install root is derived
/// Then: it is `C:\ProgramData\tegata`
#[test]
fn install_root_of_the_default_configuration_is_the_default_directory() {
    let root = install_root_under(r"C:\ProgramData", r"C:\ProgramData\tegata\config.toml")
        .expect("default configuration path is accepted");
    assert_eq!(root, r"C:\ProgramData\tegata");
}

/// Given: `%ProgramData%` = `C:\ProgramData` and a configuration in another directory
/// When: the install root is derived
/// Then: it is that directory, `C:\ProgramData\tegata-rig`
#[test]
fn install_root_of_a_named_instance_is_its_own_directory() {
    let root = install_root_under(r"C:\ProgramData", r"C:\ProgramData\tegata-rig\config.toml")
        .expect("named instance path is accepted");
    assert_eq!(root, r"C:\ProgramData\tegata-rig");
}

/// Given: `%ProgramData%` = `C:\ProgramData` and a configuration path that differs only in case
/// When: the install root is derived
/// Then: the path is accepted and returned with its own spelling
#[test]
fn install_root_comparison_ignores_case() {
    let root = install_root_under(r"C:\ProgramData", r"c:\programdata\Tegata\config.toml")
        .expect("case differences do not reject the path");
    assert_eq!(root, r"c:\programdata\Tegata");
}

/// Given: `%ProgramData%` with a trailing separator
/// When: the install root is derived for the default configuration path
/// Then: the trailing separator does not change the result
#[test]
fn install_root_normalises_a_trailing_separator_on_program_data() {
    let root = install_root_under(r"C:\ProgramData\", r"C:\ProgramData\tegata\config.toml")
        .expect("trailing separator is normalised");
    assert_eq!(root, r"C:\ProgramData\tegata");
}

/// Given: `%ProgramData%` = `C:\ProgramData` and a configuration under a user profile
/// When: the install root is derived
/// Then: it is refused with a message that names `%ProgramData%`
#[test]
fn install_root_refuses_a_configuration_outside_program_data() {
    let error = install_root_under(r"C:\ProgramData", r"C:\Users\alice\config.toml")
        .expect_err("a user profile path is refused");
    assert!(
        error.to_string().contains("%ProgramData%"),
        "error should name %ProgramData%: {error}"
    );
}

/// Given: `%ProgramData%` = `C:\ProgramData` and a configuration path with a doubled
///        separator in front of the file name
/// When: the install root is derived
/// Then: the repeated separator counts as one, so the path is refused just like
///       `C:\ProgramData\config.toml`
#[test]
fn install_root_collapses_repeated_separators_before_judging() {
    let error = install_root_under(r"C:\ProgramData", r"C:\ProgramData\\config.toml")
        .expect_err("a doubled separator does not create a directory level");
    assert!(
        error.to_string().contains("%ProgramData%"),
        "error should name %ProgramData%: {error}"
    );
    let root = install_root_under(r"C:\ProgramData", r"C:\ProgramData\tegata\\config.toml")
        .expect("a doubled separator inside an accepted path is tolerated");
    assert_eq!(root, r"C:\ProgramData\tegata");
}

/// Given: `%ProgramData%` = `C:\ProgramData` and a configuration directly inside it
/// When: the install root is derived
/// Then: it is refused, because the root would be `%ProgramData%` itself
#[test]
fn install_root_refuses_a_configuration_directly_under_program_data() {
    let error = install_root_under(r"C:\ProgramData", r"C:\ProgramData\config.toml")
        .expect_err("a configuration directly under %ProgramData% is refused");
    assert!(
        error.to_string().contains("%ProgramData%"),
        "error should name %ProgramData%: {error}"
    );
}
