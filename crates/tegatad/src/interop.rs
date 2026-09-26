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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AncestryTermination {
    ClientMissing,
    ParentMissing,
    Root,
    Cycle,
    CreationTimeReversed,
    DepthLimit,
}

impl AncestryTermination {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ClientMissing => "client_missing",
            Self::ParentMissing => "parent_missing",
            Self::Root => "root",
            Self::Cycle => "cycle",
            Self::CreationTimeReversed => "creation_time_reversed",
            Self::DepthLimit => "depth_limit",
        }
    }
}

/// 監査に記録する祖先走査の結末です。
///
/// プロセス表を取得できず走査に至らなかった場合を、走査の終了理由と区別して表します。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OriginWalk {
    Terminated(AncestryTermination),
    SnapshotFailed,
}

impl OriginWalk {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Terminated(termination) => termination.as_str(),
            Self::SnapshotFailed => "snapshot_failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AncestryTrace<'a> {
    pub(crate) chain: Vec<&'a ProcEntry>,
    pub(crate) termination: AncestryTermination,
}

pub(crate) fn trace_ancestry(client_pid: u32, table: &[ProcEntry]) -> AncestryTrace<'_> {
    // Toolhelp の表には PID 0 の System Idle Process（ppid 0）が含まれる。PID 0 をそのまま
    // 探すと Root で走査を終えて Native と判定され、PID を取得できなかった caller が
    // 管理 RPC を通る（fail-open）。これを防ぐため、client が表に無い場合と同じく扱う。
    if client_pid == 0 {
        return AncestryTrace {
            chain: Vec::new(),
            termination: AncestryTermination::ClientMissing,
        };
    }

    let mut current_pid = client_pid;
    let mut chain: Vec<&ProcEntry> = Vec::new();

    for _ in 0..=MAX_ANCESTRY_DEPTH {
        let Some(current) = table.iter().find(|entry| entry.pid == current_pid) else {
            return AncestryTrace {
                termination: if chain.is_empty() {
                    AncestryTermination::ClientMissing
                } else {
                    AncestryTermination::ParentMissing
                },
                chain,
            };
        };
        chain.push(current);
        if current.ppid == 0 {
            return AncestryTrace {
                chain,
                termination: AncestryTermination::Root,
            };
        }
        // Windows は PID を再利用するため、終了済みの祖先の PID が別プロセスに割り当てられ、
        // 親の連鎖が循環することがある。循環は正規の経路でも生じるため、終了条件として扱う。
        if chain.iter().any(|entry| entry.pid == current.ppid) {
            return AncestryTrace {
                chain,
                termination: AncestryTermination::Cycle,
            };
        }
        let Some(parent) = table.iter().find(|entry| entry.pid == current.ppid) else {
            return AncestryTrace {
                chain,
                termination: AncestryTermination::ParentMissing,
            };
        };
        // 親が子より後に作成されている場合、その PID は再利用された別プロセスである。
        // 以降の祖先は検証できないため、鎖に含めずに走査を終える。
        if let (Some(child_created), Some(parent_created)) = (current.created, parent.created)
            && parent_created > child_created
        {
            return AncestryTrace {
                chain,
                termination: AncestryTermination::CreationTimeReversed,
            };
        }
        current_pid = current.ppid;
    }

    AncestryTrace {
        chain,
        termination: AncestryTermination::DepthLimit,
    }
}

/// 走査を終えるまでに検証した祖先鎖から caller の由来を判定する。
///
/// client 自身が表に無い場合のみ `Unknown` とする。親の終了や PID 再利用による
/// 打ち切りは正規の経路でも常に生じるため、それまでの鎖で判定する。
pub(crate) fn classify_ancestry(trace: &AncestryTrace<'_>) -> Origin {
    if trace.termination == AncestryTermination::ClientMissing {
        return Origin::Unknown;
    }
    if trace
        .chain
        .iter()
        .any(|entry| is_wsl_interop_executable(&entry.exe))
    {
        Origin::WslInterop
    } else {
        Origin::Native
    }
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
    use super::{
        AncestryTermination, MAX_ANCESTRY_DEPTH, Origin, ProcEntry, classify_ancestry,
        trace_ancestry,
    };

    fn entry(pid: u32, ppid: u32, exe: &str, created: u64) -> ProcEntry {
        ProcEntry {
            pid,
            ppid,
            exe: exe.to_owned(),
            created: Some(created),
        }
    }

    fn entry_without_creation(pid: u32, ppid: u32, exe: &str) -> ProcEntry {
        ProcEntry {
            pid,
            ppid,
            exe: exe.to_owned(),
            created: None,
        }
    }

    #[test]
    fn wsl_exe_child_is_wsl_interop() {
        let table = [
            entry(10, 20, "tegatad.exe", 30),
            entry(20, 30, "wsl.exe", 20),
            entry(30, 40, "pwsh.exe", 10),
        ];

        assert_eq!(
            classify_ancestry(&trace_ancestry(10, &table)),
            Origin::WslInterop
        );
    }

    #[test]
    fn wslhost_exe_ancestor_is_wsl_interop() {
        let table = [
            entry(10, 20, "tegatad.exe", 40),
            entry(20, 30, "cmd.exe", 30),
            entry(30, 40, "wslhost.exe", 20),
            entry(40, 50, "svchost.exe", 10),
        ];

        assert_eq!(
            classify_ancestry(&trace_ancestry(10, &table)),
            Origin::WslInterop
        );
    }

    #[test]
    fn native_explorer_powershell_chain_with_missing_parent_is_native() {
        let table = [
            entry(10, 20, "powershell.exe", 30),
            entry(20, 30, "explorer.exe", 20),
        ];

        assert_eq!(
            classify_ancestry(&trace_ancestry(10, &table)),
            Origin::Native
        );
        assert_eq!(
            trace_ancestry(10, &table).termination,
            AncestryTermination::ParentMissing
        );
    }

    #[test]
    fn missing_client_pid_is_unknown() {
        let table = [entry(20, 0, "explorer.exe", 20)];

        assert_eq!(
            classify_ancestry(&trace_ancestry(10, &table)),
            Origin::Unknown
        );
    }

    #[test]
    fn zero_client_pid_is_unknown_despite_idle_process() {
        let table = [entry(0, 0, "[System Process]", 0)];

        assert_eq!(
            classify_ancestry(&trace_ancestry(0, &table)),
            Origin::Unknown
        );
    }

    #[test]
    fn reversed_creation_times_stop_before_wsl_ancestor() {
        let table = [
            entry(10, 20, "powershell.exe", 20),
            entry(20, 30, "explorer.exe", 30),
            entry(30, 0, "wsl.exe", 10),
        ];

        assert_eq!(
            classify_ancestry(&trace_ancestry(10, &table)),
            Origin::Native
        );
        assert_eq!(
            trace_ancestry(10, &table).termination,
            AncestryTermination::CreationTimeReversed
        );
    }

    #[test]
    fn uppercase_wsl_exe_is_wsl_interop() {
        let table = [
            entry(10, 20, "tegatad.exe", 20),
            entry(20, 30, "WSL.EXE", 10),
        ];

        assert_eq!(
            classify_ancestry(&trace_ancestry(10, &table)),
            Origin::WslInterop
        );
    }

    #[test]
    fn depth_limit_ends_walk_before_distant_wsl_ancestor() {
        let depth = u32::try_from(MAX_ANCESTRY_DEPTH).unwrap();
        let mut table: Vec<ProcEntry> = (1..=depth + 1)
            .map(|pid| entry_without_creation(pid, pid + 1, "cmd.exe"))
            .collect();
        table.push(entry_without_creation(depth + 2, 0, "wsl.exe"));

        assert_eq!(
            classify_ancestry(&trace_ancestry(1, &table)),
            Origin::Native
        );
        assert_eq!(
            trace_ancestry(1, &table).termination,
            AncestryTermination::DepthLimit
        );
    }

    #[test]
    fn ssh_session_cycle_is_native() {
        let table = [
            entry_without_creation(23564, 19292, "pwsh.exe"),
            entry_without_creation(19292, 15068, "sshd-session.exe"),
            entry_without_creation(15068, 5780, "sshd-session.exe"),
            entry_without_creation(5780, 2228, "sshd.exe"),
            entry_without_creation(2228, 2148, "services.exe"),
            entry_without_creation(2148, 1676, "wininit.exe"),
            entry_without_creation(1676, 2228, "svchost.exe"),
        ];

        assert_eq!(
            classify_ancestry(&trace_ancestry(23564, &table)),
            Origin::Native
        );
        assert_eq!(
            trace_ancestry(23564, &table).termination,
            AncestryTermination::Cycle
        );
    }
}
