//! Acceptance tests for the Windows instance naming helpers.
//!
//! One test per acceptance condition of the private brief. The helpers are
//! pure string logic so they run on every platform, which is what lets the
//! Linux checks guard behaviour that only the Windows service runtime uses.

use tegata_core::windows_instance::{firewall_rule_name, install_root_under, service_account};

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
