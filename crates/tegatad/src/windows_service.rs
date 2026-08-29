use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::{Config, ReadySender};

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

#[derive(clap::Subcommand)]
pub(crate) enum ServiceCommand {
    Install {
        #[arg(long)]
        config: PathBuf,
    },
    Uninstall,
}

const SERVICE_NAME: &str = "tegatad";

const SERVICE_ACCOUNT: &str = r"NT SERVICE\tegatad";

const FIREWALL_RULE_NAME: &str = "tegatad WSL TCP";

windows_service::define_windows_service!(ffi_service_main, service_main_entry);

pub(crate) const START: fn() -> windows_service::Result<()> =
    || service_dispatcher::start(SERVICE_NAME, ffi_service_main);

fn service_main_entry(arguments: Vec<OsString>) {
    let _ = service_main(arguments);
}

/// Resolves `--config` from the command line of the process.
///
/// The service control manager passes the arguments of the registered image
/// path to the process, not to `ServiceMain`, whose arguments carry only what
/// a `StartService` caller supplied. The configuration is therefore read from
/// the process command line.
fn config_path_from_command_line() -> Option<PathBuf> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if let Some(window) = arguments.windows(2).find(|window| window[0] == "--config") {
        return Some(PathBuf::from(&window[1]));
    }
    arguments.iter().find_map(|argument| {
        argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--config="))
            .map(PathBuf::from)
    })
}

fn service_main(_arguments: Vec<OsString>) -> windows_service::Result<()> {
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let stop_sender = Arc::new(std::sync::Mutex::new(Some(stop_sender)));
    let status_handle = service_control_handler::register(SERVICE_NAME, {
        let stop_sender = stop_sender.clone();
        move |control_event| match control_event {
            ServiceControl::Stop => {
                if let Some(sender) = stop_sender.lock().expect("service stop lock").take() {
                    let _ = sender.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;
    // A service that never reports a state leaves the control manager waiting
    // in `StartPending`, so a missing configuration is reported as a stop.
    let Some(config_path) = config_path_from_command_line() else {
        eprintln!("tegatad: the service command line does not contain --config");
        status_handle.set_service_status(stopped_status(
            windows_service::service::ServiceExitCode::ServiceSpecific(1),
        ))?;
        return Ok(());
    };
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(30),
        process_id: Some(std::process::id()),
    })?;

    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
    let ready_sender: ReadySender = Arc::new(std::sync::Mutex::new(Some(ready_sender)));
    let runtime_sender = ready_sender.clone();
    let runtime_handle = std::thread::spawn(move || {
        let result = run_daemon_runtime_for_service(
            &config_path,
            Some(stop_receiver),
            runtime_sender.clone(),
        )
        .map_err(|error| error.to_string());
        if let Err(error) = &result
            && let Some(sender) = runtime_sender.lock().expect("service ready lock").take()
        {
            let _ = sender.send(Err(error.clone()));
        }
        result
    });

    let startup = ready_receiver.recv();
    let mut exit_code = windows_service::service::ServiceExitCode::Win32(0);
    match startup {
        Ok(Ok(())) => {
            status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP,
                exit_code: windows_service::service::ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: Some(std::process::id()),
            })?;
        }
        Ok(Err(error)) => {
            eprintln!("tegatad: service runtime failed: {error}");
            exit_code = windows_service::service::ServiceExitCode::ServiceSpecific(1);
        }
        Err(error) => {
            let error = format!("service startup notification failed: {error}");
            eprintln!("tegatad: service runtime failed: {error}");
            exit_code = windows_service::service::ServiceExitCode::ServiceSpecific(1);
        }
    }

    match runtime_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            eprintln!("tegatad: service runtime failed: {error}");
            exit_code = windows_service::service::ServiceExitCode::ServiceSpecific(1);
        }
        Err(_) => {
            eprintln!("tegatad: service runtime thread panicked");
            exit_code = windows_service::service::ServiceExitCode::ServiceSpecific(1);
        }
    }
    status_handle.set_service_status(stopped_status(exit_code))?;
    Ok(())
}

fn stopped_status(exit_code: windows_service::service::ServiceExitCode) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

pub(crate) fn install_service(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config_text = std::fs::read_to_string(config_path)?;
    let config: Config = toml::from_str(&config_text)?;
    let service_manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![
            OsString::from("--config"),
            config_path.as_os_str().to_owned(),
        ],
        dependencies: Vec::new(),
        account_name: Some(OsString::from(SERVICE_ACCOUNT)),
        account_password: None,
    };
    service_manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    configure_firewall(config.transport.tcp_port)?;
    prepare_program_data(config_path, &config)?;
    if let Some(operator_sid) = config.transport.operator_sid.as_deref() {
        grant_service_control(operator_sid)?;
    }
    Ok(())
}

pub(crate) fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    remove_firewall_rule()?;
    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;
    Ok(())
}

fn prepare_program_data(
    config_path: &Path,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // The daemon state belongs to the service account, never to the account
    // that happened to run the installation: an interactive account that keeps
    // access would be able to read the configuration and the sealed state.
    // The local administrators group is excluded for the same reason, since
    // the WSL file server behind `/mnt/c` reads with that group enabled.
    let principals = vec![
        service_account_sid()?,
        crate::secure_fs::SDDL_SYSTEM.to_owned(),
    ];
    let root = Path::new(r"C:\ProgramData\tegata");
    let default_state = root.join("state");
    let default_browsers = root.join("browsers");
    let state = Path::new(&config.state_dir);
    let browsers = config
        .transport
        .browsers_path
        .as_deref()
        .map(Path::new)
        .unwrap_or(default_browsers.as_path());
    for path in [
        root,
        default_state.as_path(),
        default_browsers.as_path(),
        state,
        browsers,
    ] {
        std::fs::create_dir_all(path)?;
        restrict_windows_path(path, true, &principals)?;
    }
    if config_path.starts_with(root) {
        restrict_windows_path(config_path, false, &principals)?;
    }
    Ok(())
}

fn restrict_windows_path(
    path: &Path,
    directory: bool,
    principals: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    crate::secure_fs::restrict_path(path, directory, principals)?;
    Ok(())
}

/// Resolves the SID of the virtual account the service runs under.
fn service_account_sid() -> Result<String, Box<dyn std::error::Error>> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};

    let name = OsStr::new(SERVICE_ACCOUNT)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut sid_size = 0_u32;
    let mut domain_size = 0_u32;
    let mut use_kind: SID_NAME_USE = 0;
    // SAFETY: No output buffers are passed for the size query.
    unsafe {
        let _ = LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            null_mut(),
            &mut sid_size,
            null_mut(),
            &mut domain_size,
            &mut use_kind,
        );
    }
    if sid_size == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut sid = vec![0_u64; (sid_size as usize).div_ceil(size_of::<u64>())];
    let mut domain = vec![0_u16; domain_size.max(1) as usize];
    // SAFETY: Both buffers are sized as reported by the preceding size query.
    let resolved = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut use_kind,
        )
    };
    if resolved == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut string_sid = null_mut();
    // SAFETY: `sid` holds the SID written by LookupAccountNameW.
    if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut string_sid) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut length = 0;
    // SAFETY: The conversion result is a NUL-terminated UTF-16 string.
    while unsafe { *string_sid.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `string_sid` points to `length` initialized UTF-16 code units.
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(string_sid, length) });
    // SAFETY: `string_sid` is the allocated region returned by ConvertSidToStringSidW.
    unsafe {
        let _ = LocalFree(string_sid.cast());
    }
    Ok(value)
}

fn configure_firewall(tcp_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    if tcp_port == 0 {
        return Ok(());
    }
    run_powershell(&format!(
        "New-NetFirewallRule -DisplayName '{}' -Direction Inbound -Action Allow -Protocol TCP -LocalPort {} -InterfaceAlias 'vEthernet (WSL*' -Profile Any",
        FIREWALL_RULE_NAME, tcp_port
    ))
}

fn remove_firewall_rule() -> Result<(), Box<dyn std::error::Error>> {
    run_powershell(&format!(
        "Get-NetFirewallRule -DisplayName '{}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
        FIREWALL_RULE_NAME
    ))
}

fn grant_service_control(operator_sid: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !operator_sid.starts_with("S-1-") {
        return Err("operator_sid must be a Windows SID".into());
    }
    let output = std::process::Command::new("sc.exe")
        .args(["sdshow", SERVICE_NAME])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(String::from_utf8_lossy(&output.stderr)).into());
    }
    let descriptor = String::from_utf8(output.stdout)?;
    let descriptor = descriptor
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("D:"))
        .ok_or("sc.exe sdshow returned no security descriptor")?;
    let ace = format!("(A;;LCRPWP;;;{operator_sid})");
    let insert_at = descriptor.find("S:").unwrap_or(descriptor.len());
    let updated = format!(
        "{}{}{}",
        &descriptor[..insert_at],
        ace,
        &descriptor[insert_at..]
    );
    run_windows_command(
        "sc.exe",
        &["sdset".to_owned(), SERVICE_NAME.to_owned(), updated],
    )
}

fn run_powershell(script: &str) -> Result<(), Box<dyn std::error::Error>> {
    run_windows_command(
        "powershell.exe",
        &[
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            script.to_owned(),
        ],
    )
}

fn run_windows_command(
    program: &str,
    arguments: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    ))
    .into())
}
fn run_daemon_runtime_for_service(
    config_path: &Path,
    stop: Option<tokio::sync::oneshot::Receiver<()>>,
    ready_sender: ReadySender,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(super::run_daemon(
            config_path,
            false,
            stop,
            Some(ready_sender),
        ))
}
