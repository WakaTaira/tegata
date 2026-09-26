#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Origin {
    Native,
    WslInterop,
    Unknown,
}

impl Origin {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::WslInterop => "wsl_interop",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcEntry {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    pub(crate) exe: String,
    pub(crate) created: Option<u64>,
}

pub(crate) const MAX_ANCESTRY_DEPTH: usize = 32;

pub(crate) fn classify_ancestry(client_pid: u32, table: &[ProcEntry]) -> Origin {
    let mut current_pid = client_pid;
    let mut visited = Vec::new();

    for _ in 0..=MAX_ANCESTRY_DEPTH {
        let Some(current) = table.iter().find(|entry| entry.pid == current_pid) else {
            return Origin::Unknown;
        };
        if current.ppid == 0 {
            return if is_wsl_interop_executable(&current.exe) {
                Origin::WslInterop
            } else {
                Origin::Native
            };
        }
        if current.ppid == current.pid || visited.contains(&current.ppid) {
            return Origin::Unknown;
        }
        let Some(parent) = table.iter().find(|entry| entry.pid == current.ppid) else {
            return if is_wsl_interop_executable(&current.exe) {
                Origin::WslInterop
            } else {
                Origin::Unknown
            };
        };
        if let (Some(child_created), Some(parent_created)) = (current.created, parent.created)
            && parent_created > child_created
        {
            return Origin::Unknown;
        }
        if is_wsl_interop_executable(&current.exe) {
            return Origin::WslInterop;
        }
        visited.push(current.pid);
        current_pid = current.ppid;
    }

    Origin::Unknown
}

fn is_wsl_interop_executable(exe: &str) -> bool {
    let basename = exe.rsplit(['\\', '/']).next().unwrap_or(exe);
    [
        "wsl.exe",
        "wslhost.exe",
        "wslservice.exe",
        "wslrelay.exe",
        "wslg.exe",
    ]
    .iter()
    .any(|name| basename.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::{Origin, ProcEntry, classify_ancestry};

    fn entry(pid: u32, ppid: u32, exe: &str, created: u64) -> ProcEntry {
        ProcEntry {
            pid,
            ppid,
            exe: exe.to_owned(),
            created: Some(created),
        }
    }

    #[test]
    fn wsl_exe_ancestor_is_wsl_interop() {
        let table = [
            entry(10, 20, "powershell.exe", 30),
            entry(20, 0, "wsl.exe", 20),
        ];

        assert_eq!(classify_ancestry(10, &table), Origin::WslInterop);
    }

    #[test]
    fn wslhost_exe_ancestor_is_wsl_interop() {
        let table = [
            entry(10, 20, "cmd.exe", 30),
            entry(20, 0, "wslhost.exe", 20),
        ];

        assert_eq!(classify_ancestry(10, &table), Origin::WslInterop);
    }

    #[test]
    fn native_explorer_powershell_chain_is_native() {
        let table = [
            entry(10, 20, "powershell.exe", 30),
            entry(20, 0, "explorer.exe", 20),
        ];

        assert_eq!(classify_ancestry(10, &table), Origin::Native);
    }

    #[test]
    fn missing_client_pid_is_unknown() {
        let table = [entry(20, 0, "explorer.exe", 20)];

        assert_eq!(classify_ancestry(10, &table), Origin::Unknown);
    }

    #[test]
    fn reversed_creation_times_stop_with_unknown() {
        let table = [
            entry(10, 20, "powershell.exe", 20),
            entry(20, 0, "explorer.exe", 30),
        ];

        assert_eq!(classify_ancestry(10, &table), Origin::Unknown);
    }

    #[test]
    fn uppercase_wsl_exe_is_wsl_interop() {
        let table = [entry(10, 0, "WSL.EXE", 10)];

        assert_eq!(classify_ancestry(10, &table), Origin::WslInterop);
    }

    #[test]
    fn parent_cycle_stops_with_unknown() {
        let table = [
            entry(10, 20, "powershell.exe", 20),
            entry(20, 10, "explorer.exe", 10),
        ];

        assert_eq!(classify_ancestry(10, &table), Origin::Unknown);
    }
}
