//! Names derived from Windows service instance names and install roots.
//!
//! These pure functions can be tested on every platform.

const INVALID_CONFIGURATION_PATH: &str = "the configuration must live in its own directory directly under %ProgramData%, e.g. C:\\ProgramData\\tegata\\config.toml";

/// Returns the virtual service account name for a Windows service instance.
pub fn service_account(name: &str) -> String {
    format!(r"NT SERVICE\{name}")
}

/// Returns the Windows Firewall rule name for a service instance.
pub fn firewall_rule_name(name: &str) -> String {
    format!("{name} WSL TCP")
}

/// Validates a service name before embedding it in PowerShell script strings or `sc.exe` arguments.
/// This name is embedded in PowerShell script strings for firewall rules and in `sc.exe` arguments,
/// so shell metacharacters are rejected here.
pub fn validate_service_name(name: &str) -> Result<(), String> {
    if !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || b"-_.".contains(&character))
    {
        return Ok(());
    }
    Err(
        "service_name must be 1 to 256 characters of ASCII letters, digits, '-', '_' and '.'"
            .to_owned(),
    )
}

/// Returns the configuration's parent directory when it is directly under `%ProgramData%`.
pub fn install_root_under(program_data: &str, config_path: &str) -> Result<String, String> {
    let config_directory = parent_directory(config_path);
    let install_root = parent_directory(&config_directory);
    let normalized_program_data = normalize_for_comparison(program_data);
    let normalized_install_root = normalize_for_comparison(&install_root);

    if !config_directory.is_empty() && normalized_install_root == normalized_program_data {
        Ok(config_directory)
    } else {
        Err(INVALID_CONFIGURATION_PATH.to_owned())
    }
}

fn parent_directory(path: &str) -> String {
    let path = path.trim_end_matches(['\\', '/']);
    path.rfind(['\\', '/'])
        .map(|separator| path[..separator].trim_end_matches(['\\', '/']).to_owned())
        .unwrap_or_default()
}

fn normalize_for_comparison(path: &str) -> String {
    path.trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_ascii_lowercase()
}
