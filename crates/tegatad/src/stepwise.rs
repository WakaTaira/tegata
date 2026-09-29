//! 段階ログイン（`login_begin` / `login_step`）。
//!
//! 段階ログインのブラウザは、ハンドオフ（`success_selector` の一致）まではこの台帳にのみ置き、
//! `DaemonState::browsers` には登録しない。ハンドオフの時点で `login` と同じ規則のブラウザ
//! セッションへ昇格させる。ハンドオフ前の応答には CDP endpoint を載せない。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tegata_core::wire::{ExecutorResponse, RpcRequest};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::{Instant, interval, timeout};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::sessions::{BrowserKey, StartControl, StartKey};
use crate::transport::PeerIdentity;
use crate::{
    AuditFields, AuditPeer, BrowserRegistration, CookieAudit, EXECUTOR_OPERATION_TIMEOUT,
    EXECUTOR_SHUTDOWN_TIMEOUT, EXECUTOR_TIMEOUT, ErrorCode, ExecutorFailure, ExecutorHandle,
    HandledRequest, SharedState, append_audit, classified, classified_with_step, cookie_store,
    current_totp, gate_on_approval, join_browser, kill_executor_handle, open_executor_with,
    parse_error_code, parse_params, register_login_browser, resolve_unlocked_credential,
    save_cookies, selector_step, service_launch_settings, start_control, stop_child, success,
    wait_or_kill_executor,
};

/// `stepwise_idle_secs` の既定値。
pub(crate) const DEFAULT_IDLE_SECS: u64 = 120;
/// `stepwise_max_secs` の既定値。
pub(crate) const DEFAULT_MAX_SECS: u64 = 600;
/// 1 回の段階ログインで受け付ける `login_step` の上限。
const MAX_STEPS: usize = 40;
/// `fill_submit` の `fills` の上限。
const MAX_FILLS: usize = 3;
const USERNAME_PLACEHOLDER: &str = "{{username}}";
const PASSWORD_PLACEHOLDER: &str = "{{password}}";
const TOTP_PLACEHOLDER: &str = "{{totp}}";
const ACTION_KINDS: [&str; 6] = [
    "click",
    "wait_for",
    "fill",
    "fill_submit",
    "snapshot",
    "abort",
];

#[derive(Deserialize)]
struct BeginParams {
    cred_id: String,
    target_url: String,
    success_selector: String,
    #[serde(default)]
    failure_selector: Option<String>,
    #[serde(default)]
    exclusive: bool,
}

#[derive(Debug, Deserialize)]
struct StepParams {
    login_id: String,
    #[serde(flatten)]
    action: StepAction,
}

/// `login_step` の action。executor へはこの形のまま（`action` と各フィールドを平坦に）送る。
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum StepAction {
    Click {
        selector: String,
    },
    WaitFor {
        selector: String,
    },
    Fill {
        selector: String,
        value: String,
    },
    FillSubmit {
        fills: Vec<FillField>,
        submit: Submit,
    },
    Snapshot,
    Abort,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct FillField {
    selector: String,
    value: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Submit {
    Click(String),
    PressEnter(String),
}

impl StepAction {
    /// 値がプレースホルダであり、secret（`{{password}}` / `{{totp}}`）が `fill_submit` の中にだけ現れるかを判定する。
    fn is_valid(&self) -> bool {
        match self {
            Self::Fill { value, .. } => value == USERNAME_PLACEHOLDER,
            Self::FillSubmit { fills, .. } => {
                (1..=MAX_FILLS).contains(&fills.len())
                    && fills.iter().all(|fill| {
                        matches!(
                            fill.value.as_str(),
                            USERNAME_PLACEHOLDER | PASSWORD_PLACEHOLDER | TOTP_PLACEHOLDER
                        )
                    })
            }
            _ => true,
        }
    }

    /// 現在の TOTP コードを executor へ渡す必要があるかを判定する。
    fn needs_totp(&self) -> bool {
        matches!(self, Self::FillSubmit { fills, .. } if fills.iter().any(|fill| fill.value == TOTP_PLACEHOLDER))
    }
}

/// `login_step` の params を解釈し、値の検証まで行う。不正は既存の不正 params と同じ `INTERNAL` とする。
fn parse_step_params(params: &Value) -> Result<StepParams, ErrorCode> {
    let params = parse_params::<StepParams>(params)?;
    if !params.action.is_valid() {
        return Err(ErrorCode::Internal);
    }
    Ok(params)
}

/// `login_step` の監査行に載せる action の種別名。既知の種別でなければ載せない。
pub(crate) fn audit_action(params: &Value) -> Option<String> {
    params
        .get("action")
        .and_then(Value::as_str)
        .filter(|action| ACTION_KINDS.contains(action))
        .map(ToOwned::to_owned)
}

/// `login_step` の監査行に載せる login_id。UUID の形でなければ載せない。
pub(crate) fn audit_login_id(params: &Value) -> Option<String> {
    params
        .get("login_id")
        .and_then(Value::as_str)
        .and_then(|login_id| Uuid::parse_str(login_id).ok())
        .map(|login_id| login_id.to_string())
}

/// executor への `login_begin` 要求。`cookies` は復元する保管済み cookie であり、復元しない場合は null とする。
#[derive(Serialize)]
struct ExecutorBeginRequest<'a> {
    op: &'static str,
    id: u64,
    target_url: &'a str,
    success_selector: &'a str,
    failure_selector: Option<&'a str>,
    secret: BeginSecret,
    cookies: Option<&'a [cookie_store::Cookie]>,
}

#[derive(Serialize)]
struct BeginSecret {
    username: String,
    password: String,
}

impl Drop for BeginSecret {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

/// executor への `login_step` 要求。`totp` は `{{totp}}` を含む `fill_submit` でのみ値を持つ。
#[derive(Serialize)]
struct ExecutorStepRequest<'a> {
    op: &'static str,
    id: u64,
    #[serde(flatten)]
    action: &'a StepAction,
    totp: Option<String>,
}

impl Drop for ExecutorStepRequest<'_> {
    fn drop(&mut self) {
        self.totp.zeroize();
    }
}

/// executor が段階ログインの要求に返した状態。
enum ExecutorState {
    Pending(Value),
    Done(DoneState),
    Aborted,
}

/// ハンドオフに用いる executor の `done` 応答の値。
struct DoneState {
    endpoint: String,
    target_id: String,
    cookies: Option<Value>,
    steps_skipped: bool,
}

/// executor の `login_begin` / `login_step` への応答行を解釈する。`id` が一致しない応答は `INTERNAL` とする。
fn parse_state_response(line: &str, id: u64) -> Result<ExecutorState, ExecutorFailure> {
    let mut value: Value = serde_json::from_str(line).map_err(|_| ErrorCode::Internal)?;
    if value.get("id").and_then(Value::as_u64) != Some(id) {
        return Err(ErrorCode::Internal.into());
    }
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        let response: ExecutorResponse =
            serde_json::from_value(value).map_err(|_| ErrorCode::Internal)?;
        let code = response
            .error
            .as_deref()
            .map(parse_error_code)
            .unwrap_or(ErrorCode::Internal);
        return Err(ExecutorFailure {
            code,
            step: selector_step(&response, code),
        });
    }
    match value.get("state").and_then(Value::as_str) {
        Some("pending") => value
            .get_mut("snapshot")
            .map(Value::take)
            .filter(Value::is_object)
            .map(ExecutorState::Pending)
            .ok_or_else(|| ErrorCode::Internal.into()),
        Some("done") => parse_done(&mut value).map(ExecutorState::Done),
        Some("aborted") => Ok(ExecutorState::Aborted),
        _ => Err(ErrorCode::Internal.into()),
    }
}

fn parse_done(value: &mut Value) -> Result<DoneState, ExecutorFailure> {
    let text = |value: &Value, key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or(ErrorCode::Internal)
    };
    Ok(DoneState {
        endpoint: text(value, "endpoint")?,
        target_id: text(value, "target_id")?,
        cookies: value
            .get_mut("cookies")
            .map(Value::take)
            .filter(|cookies| !cookies.is_null()),
        steps_skipped: value
            .get("steps_skipped")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// ハンドオフ前の executor 接続と、次に送る要求の id。
pub(crate) struct PendingExecutor {
    handle: ExecutorHandle,
    next_id: u64,
}

impl PendingExecutor {
    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

/// executor 接続の置き場。同じ段階ログインの `login_step` はこの Mutex で直列化する。
/// 終了処理は中身を取り出して `None` にする。
type Slot = Arc<Mutex<Option<PendingExecutor>>>;

/// 台帳の 1 件。
pub(crate) struct Entry {
    key: BrowserKey,
    exclusive: bool,
    persist_cookies: bool,
    browser_started_at: Instant,
    last_active: Instant,
    /// 処理中の `login_step` の数。0 のときに限りアイドル期限を適用する。
    in_flight: usize,
    steps: usize,
    /// executor へ渡した TOTP コードの数。
    totp_entered: usize,
    slot: Slot,
}

impl Entry {
    fn new(
        key: BrowserKey,
        exclusive: bool,
        persist_cookies: bool,
        browser_started_at: Instant,
        now: Instant,
        slot: Slot,
    ) -> Self {
        Self {
            key,
            exclusive,
            persist_cookies,
            browser_started_at,
            last_active: now,
            in_flight: 0,
            steps: 0,
            totp_entered: 0,
            slot,
        }
    }
}

/// `login_step` の受付結果。
enum Claim {
    NotFound,
    /// 期限切れを検出して台帳から除いた。
    Expired(Entry),
    /// `login_step` の上限を超えたため台帳から除いた。
    Exhausted(Entry),
    Ready(Ticket),
}

/// 受け付けた `login_step` の実行に要る値。
struct Ticket {
    key: BrowserKey,
    exclusive: bool,
    persist_cookies: bool,
    browser_started_at: Instant,
    slot: Slot,
}

/// login_id から段階ログインを引く台帳。デーモンの状態の Mutex の下で操作する。
pub(crate) struct Ledger {
    entries: HashMap<String, Entry>,
    idle: Duration,
    max: Duration,
}

impl Ledger {
    pub(crate) fn new(idle: Duration, max: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            idle,
            max,
        }
    }

    fn insert(&mut self, login_id: String, entry: Entry) {
        self.entries.insert(login_id, entry);
    }

    fn is_expired(&self, entry: &Entry, now: Instant) -> bool {
        now >= entry.browser_started_at + self.max
            || (entry.in_flight == 0 && now >= entry.last_active + self.idle)
    }

    /// 呼び出し元の段階ログインであれば 1 回の `login_step` として受け付ける。
    /// 他の principal の login_id は存在しないものとして扱う。
    fn claim(&mut self, login_id: &str, principal: &str, now: Instant) -> Claim {
        let Some(entry) = self.entries.get(login_id) else {
            return Claim::NotFound;
        };
        if entry.key.principal != principal {
            return Claim::NotFound;
        }
        if self.is_expired(entry, now) {
            return self
                .entries
                .remove(login_id)
                .map_or(Claim::NotFound, Claim::Expired);
        }
        let entry = self.entries.get_mut(login_id).expect("entry checked above");
        entry.steps += 1;
        if entry.steps > MAX_STEPS {
            return self
                .entries
                .remove(login_id)
                .map_or(Claim::NotFound, Claim::Exhausted);
        }
        entry.in_flight += 1;
        Claim::Ready(Ticket {
            key: entry.key.clone(),
            exclusive: entry.exclusive,
            persist_cookies: entry.persist_cookies,
            browser_started_at: entry.browser_started_at,
            slot: entry.slot.clone(),
        })
    }

    fn current_mut(&mut self, login_id: &str, slot: &Slot) -> Option<&mut Entry> {
        self.entries
            .get_mut(login_id)
            .filter(|entry| Arc::ptr_eq(&entry.slot, slot))
    }

    /// 受け付けた `login_step` の段階ログインが、まだ終了されていないかを判定する。
    fn is_current(&self, login_id: &str, slot: &Slot) -> bool {
        self.entries
            .get(login_id)
            .is_some_and(|entry| Arc::ptr_eq(&entry.slot, slot))
    }

    /// `login_step` の完了を記録し、アイドル期限の起点を応答の時刻へ進める。
    fn release(&mut self, login_id: &str, slot: &Slot, now: Instant) {
        if let Some(entry) = self.current_mut(login_id, slot) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
            entry.last_active = now;
        }
    }

    fn note_totp(&mut self, login_id: &str, slot: &Slot) {
        if let Some(entry) = self.current_mut(login_id, slot) {
            entry.totp_entered += 1;
        }
    }

    fn remove_current(&mut self, login_id: &str, slot: &Slot) -> Option<Entry> {
        if !self.is_current(login_id, slot) {
            return None;
        }
        self.entries.remove(login_id)
    }

    /// 期限切れの段階ログインを台帳から除いて返す。
    fn take_expired(&mut self, now: Instant) -> Vec<(String, Entry)> {
        let expired = self
            .entries
            .iter()
            .filter(|(_, entry)| self.is_expired(entry, now))
            .map(|(login_id, _)| login_id.clone())
            .collect::<Vec<_>>();
        self.take_ids(expired)
    }

    /// principal の段階ログインを台帳から除いて返す。
    fn take_principal(&mut self, principal: &str) -> Vec<(String, Entry)> {
        let selected = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.key.principal == principal)
            .map(|(login_id, _)| login_id.clone())
            .collect::<Vec<_>>();
        self.take_ids(selected)
    }

    /// principal の段階ログインであれば台帳から除いて返す。
    fn take_owned(&mut self, login_id: &str, principal: &str) -> Option<Entry> {
        if self.entries.get(login_id)?.key.principal != principal {
            return None;
        }
        self.entries.remove(login_id)
    }

    /// namespace（`None` は全体）の段階ログインを台帳から除いて返す。
    fn take_namespace(&mut self, namespace: Option<&str>) -> Vec<(String, Entry)> {
        let selected = self
            .entries
            .iter()
            .filter(|(_, entry)| namespace.is_none_or(|namespace| namespace == entry.key.namespace))
            .map(|(login_id, _)| login_id.clone())
            .collect::<Vec<_>>();
        self.take_ids(selected)
    }

    fn take_ids(&mut self, login_ids: Vec<String>) -> Vec<(String, Entry)> {
        login_ids
            .into_iter()
            .filter_map(|login_id| {
                let entry = self.entries.remove(&login_id)?;
                Some((login_id, entry))
            })
            .collect()
    }
}

/// 段階ログインの終了理由。監査の method・outcome とレート制限への計上を決める。
#[derive(Clone, Copy)]
pub(crate) enum EndReason {
    Rejected,
    Expired,
    Aborted,
    Failed(ErrorCode),
    LockVault,
    Shutdown,
    PeerRevoked,
}

impl EndReason {
    fn from_failure(code: ErrorCode) -> Self {
        match code {
            ErrorCode::SnapshotRejected => Self::Rejected,
            code => Self::Failed(code),
        }
    }

    fn audit_method(self) -> &'static str {
        match self {
            Self::Rejected => "stepwise_rejected",
            Self::Expired => "stepwise_expired",
            Self::Aborted => "stepwise_aborted",
            Self::Failed(_) | Self::LockVault | Self::Shutdown | Self::PeerRevoked => {
                "stepwise_terminated"
            }
        }
    }

    fn outcome(self) -> &'static str {
        match self {
            Self::Rejected => ErrorCode::SnapshotRejected.as_str(),
            Self::Expired | Self::Aborted => "ok",
            Self::Failed(code) => code.as_str(),
            Self::LockVault => "lock_vault",
            Self::Shutdown => "shutdown",
            Self::PeerRevoked => "peer_revoked",
        }
    }

    /// 1 回のログイン失敗としてレート制限のバックオフに数えるか。
    fn counts_as_failure(self) -> bool {
        matches!(
            self,
            Self::Rejected
                | Self::Expired
                | Self::Failed(ErrorCode::FillMismatch | ErrorCode::InvalidCredential)
        )
    }
}

pub(crate) async fn login_begin(
    request: &RpcRequest,
    state: SharedState,
    peer: &PeerIdentity,
) -> HandledRequest {
    let params = match parse_params::<BeginParams>(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(request.id.clone(), error),
    };
    let Some((namespace, _)) = params.cred_id.split_once(':') else {
        return classified(request.id.clone(), ErrorCode::InvalidCredential);
    };
    let key = BrowserKey::new(
        peer.principal(),
        namespace.to_owned(),
        params.cred_id.clone(),
    );
    let grant = match gate_on_approval(
        &state,
        &params.cred_id,
        &params.target_url,
        "login_begin",
        peer,
    )
    .await
    {
        Ok(grant) => grant,
        Err(error) => return classified(request.id.clone(), error),
    };
    begin_after_approval(request.id.clone(), &state, key, &params)
        .await
        .with_audit_approval_grant(grant)
}

/// 承認ゲートを通過した `login_begin` について、相乗り・レート制限・資格の解決・executor の起動を行う。
/// 起動制御はこの間だけ保持し、`pending` の間は保持しない。
async fn begin_after_approval(
    id: Value,
    state: &SharedState,
    key: BrowserKey,
    params: &BeginParams,
) -> HandledRequest {
    let gate = start_control(state, StartKey::Browser(key.clone())).await;
    let mut control = gate.lock().await;
    if !params.exclusive
        && let Some(result) = join_browser(state, &key, &key.principal).await
    {
        return match result {
            Ok(result) => success(id, done_result(result)).with_audit_shared(true),
            Err(error) => classified(id, error),
        };
    }
    if control.is_limited(Instant::now()) {
        return classified(id, ErrorCode::RateLimited);
    }
    let credential = match resolve_unlocked_credential(state, &params.cred_id).await {
        Ok(credential) => credential,
        Err(error) => return classified(id, error),
    };
    let settings = service_launch_settings(state).await;
    let cookie_store = state.lock().await.cookie_store.clone();
    // 承認ゲートとアンロック確認を通過した後にのみ、保管済み cookie を読み出す。
    let persist_cookies = cookie_store.persists(&params.cred_id);
    let restored = persist_cookies
        .then(|| cookie_store.load(&key, cookie_store::unix_now()))
        .flatten();
    control.record_attempt(Instant::now());
    let browser_started_at = Instant::now();
    let build_request = || ExecutorBeginRequest {
        op: "login_begin",
        id: 1,
        target_url: &params.target_url,
        success_selector: &params.success_selector,
        failure_selector: params.failure_selector.as_deref(),
        secret: BeginSecret {
            username: credential.username.as_str().to_owned(),
            password: credential.password.as_str().to_owned(),
        },
        cookies: restored.as_deref(),
    };
    let opened = open_executor_with(
        &settings.executor_entry,
        settings.executor_socket.as_deref(),
        &settings.node_path,
        settings.browsers_path.as_deref(),
        build_request,
        |line| parse_state_response(line, 1),
    )
    .await;
    drop(credential);
    let (reply, handle) = match opened {
        Ok(opened) => opened,
        Err(failure) => {
            control.record_failure(Instant::now());
            return classified_with_step(id, failure.code, failure.step);
        }
    };
    let launched = Launched {
        key,
        exclusive: params.exclusive,
        persist_cookies,
        browser_started_at,
        pending: PendingExecutor { handle, next_id: 2 },
    };
    let restored = restored.is_some();
    match reply {
        ExecutorState::Pending(snapshot) => {
            drop(control);
            let login_id = register_pending(state, launched).await;
            success(id, pending_result(&login_id, snapshot))
                .with_audit_cookies(persist_cookies.then(|| CookieAudit::login(restored, false)))
        }
        ExecutorState::Done(done) => {
            let steps_skipped = done.steps_skipped;
            match hand_off(state, &mut control, launched, done).await {
                Ok(result) => success(id, result)
                    .with_audit_shared(false)
                    .with_audit_cookies(
                        persist_cookies.then(|| CookieAudit::login(restored, steps_skipped)),
                    ),
                Err(error) => classified(id, error),
            }
        }
        ExecutorState::Aborted => {
            stop_child(launched.pending.handle).await;
            control.record_failure(Instant::now());
            classified(id, ErrorCode::Internal)
        }
    }
}

/// 起動した段階ログインのブラウザと、その起動時の条件。
struct Launched {
    key: BrowserKey,
    exclusive: bool,
    persist_cookies: bool,
    browser_started_at: Instant,
    pending: PendingExecutor,
}

/// `pending` の段階ログインを台帳へ登録し、login_id を返す。
async fn register_pending(state: &SharedState, launched: Launched) -> String {
    let login_id = Uuid::new_v4().to_string();
    let Launched {
        key,
        exclusive,
        persist_cookies,
        browser_started_at,
        pending,
    } = launched;
    let slot = Arc::new(Mutex::new(Some(pending)));
    let entry = Entry::new(
        key,
        exclusive,
        persist_cookies,
        browser_started_at,
        Instant::now(),
        slot,
    );
    state.lock().await.stepwise.insert(login_id.clone(), entry);
    login_id
}

fn pending_result(login_id: &str, snapshot: Value) -> Value {
    json!({ "state": "pending", "login_id": login_id, "snapshot": snapshot })
}

/// `login` と同じ形の成功応答に `state: "done"` を加える。
fn done_result(mut result: Value) -> Value {
    if let Some(object) = result.as_object_mut() {
        object.insert("state".to_owned(), json!("done"));
    }
    result
}

/// 段階ログインのブラウザを通常のブラウザセッションへ昇格させる。呼び出し元は起動制御を保持していること。
/// 同じ鍵の共有セッションが既にあれば、非共有のセッションとして登録する。
async fn hand_off(
    state: &SharedState,
    control: &mut StartControl,
    launched: Launched,
    done: DoneState,
) -> Result<Value, ErrorCode> {
    control.record_success();
    let (shared_exists, cookie_store) = {
        let daemon = state.lock().await;
        (
            daemon.shared_browsers.contains_key(&launched.key),
            daemon.cookie_store.clone(),
        )
    };
    let registration = BrowserRegistration {
        key: launched.key.clone(),
        principal: launched.key.principal.clone(),
        exclusive: launched.exclusive || shared_exists,
        persist_cookies: launched.persist_cookies,
        endpoint: done.endpoint,
        target_id: done.target_id,
        executor: launched.pending.handle,
        next_id: launched.pending.next_id,
        browser_started_at: launched.browser_started_at,
    };
    let result = register_login_browser(state, registration).await?;
    if launched.persist_cookies
        && let Some(cookies) = done.cookies.as_ref()
    {
        save_cookies(&cookie_store, &launched.key, cookies);
    }
    Ok(done_result(result))
}

pub(crate) async fn login_step(
    request: &RpcRequest,
    state: SharedState,
    peer: &PeerIdentity,
) -> HandledRequest {
    let id = request.id.clone();
    let params = match parse_step_params(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(id, error),
    };
    let login_id = params.login_id.as_str();
    let claim = state
        .lock()
        .await
        .stepwise
        .claim(login_id, &peer.principal(), Instant::now());
    match claim {
        Claim::NotFound => classified(id, ErrorCode::NotFound),
        Claim::Expired(entry) => {
            end_entry(
                &state,
                login_id,
                entry,
                EndReason::Expired,
                AuditPeer::System,
            )
            .await;
            classified(id, ErrorCode::NotFound)
        }
        Claim::Exhausted(entry) => {
            let reason = EndReason::Failed(ErrorCode::RateLimited);
            end_entry(&state, login_id, entry, reason, AuditPeer::Peer(peer)).await;
            classified(id, ErrorCode::RateLimited)
        }
        Claim::Ready(ticket) => run_step(&state, peer, id, login_id, &params.action, ticket).await,
    }
}

/// executor の応答を受けた後の扱い。
enum Next {
    /// 段階ログインを続ける（`pending` のスナップショット、または `SELECTOR_NOT_FOUND`）。
    Continue(Result<Value, ExecutorFailure>),
    Handoff(DoneState),
    End(EndReason, ExecutorFailure),
}

fn next_after(outcome: Result<ExecutorState, ExecutorFailure>) -> Next {
    match outcome {
        Ok(ExecutorState::Pending(snapshot)) => Next::Continue(Ok(snapshot)),
        Ok(ExecutorState::Done(done)) => Next::Handoff(done),
        Ok(ExecutorState::Aborted) => Next::End(
            EndReason::Failed(ErrorCode::Internal),
            ErrorCode::Internal.into(),
        ),
        Err(failure) if matches!(failure.code, ErrorCode::SelectorNotFound) => {
            Next::Continue(Err(failure))
        }
        Err(failure) => Next::End(EndReason::from_failure(failure.code), failure),
    }
}

/// 受け付けた `login_step` を、同じ段階ログインの他の step と直列に executor へ送る。
async fn run_step(
    state: &SharedState,
    peer: &PeerIdentity,
    id: Value,
    login_id: &str,
    action: &StepAction,
    ticket: Ticket,
) -> HandledRequest {
    let mut slot = ticket.slot.lock().await;
    // 待機中に終了された段階ログインは、終了処理が executor を回収する。
    let current = state
        .lock()
        .await
        .stepwise
        .is_current(login_id, &ticket.slot);
    let Some(pending) = slot.as_mut().filter(|_| current) else {
        return classified(id, ErrorCode::NotFound);
    };
    if matches!(action, StepAction::Abort) {
        let pending = slot.take();
        drop(slot);
        state
            .lock()
            .await
            .stepwise
            .remove_current(login_id, &ticket.slot);
        finish(
            state,
            login_id,
            &ticket.key,
            pending,
            EndReason::Aborted,
            AuditPeer::Peer(peer),
        )
        .await;
        return success(id, json!({ "state": "aborted" }));
    }
    let totp = match step_totp(state, action, &ticket.key.cred_id).await {
        Ok(totp) => totp,
        Err(error) => {
            state
                .lock()
                .await
                .stepwise
                .release(login_id, &ticket.slot, Instant::now());
            return classified(id, error);
        }
    };
    if totp.is_some() {
        state
            .lock()
            .await
            .stepwise
            .note_totp(login_id, &ticket.slot);
    }
    let next = next_after(exchange_step(pending, action, totp, EXECUTOR_TIMEOUT).await);
    let ended = {
        let mut daemon = state.lock().await;
        if !daemon.stepwise.is_current(login_id, &ticket.slot) {
            return classified(id, ErrorCode::NotFound);
        }
        if matches!(next, Next::Continue(_)) {
            daemon
                .stepwise
                .release(login_id, &ticket.slot, Instant::now());
            None
        } else {
            daemon.stepwise.remove_current(login_id, &ticket.slot)
        }
    };
    let pending = if ended.is_some() { slot.take() } else { None };
    drop(slot);
    match next {
        Next::Continue(Ok(snapshot)) => success(id, pending_result(login_id, snapshot)),
        Next::Continue(Err(failure)) => classified_with_step(id, failure.code, failure.step),
        Next::Handoff(done) => {
            hand_off_step(state, peer, id, login_id, ticket, pending, done).await
        }
        Next::End(reason, failure) => {
            if let (EndReason::Rejected, Some(entry)) = (reason, ended.as_ref()) {
                eprintln!(
                    "tegatad: stepwise login {login_id} ended: snapshot rejected after {} steps ({} TOTP codes entered)",
                    entry.steps, entry.totp_entered
                );
            }
            finish(
                state,
                login_id,
                &ticket.key,
                pending,
                reason,
                AuditPeer::Peer(peer),
            )
            .await;
            classified_with_step(id, failure.code, failure.step)
        }
    }
}

/// `{{totp}}` を含む `fill_submit` であれば、資格を解決して現在の TOTP コードを返す。
async fn step_totp(
    state: &SharedState,
    action: &StepAction,
    cred_id: &str,
) -> Result<Option<String>, ErrorCode> {
    if !action.needs_totp() {
        return Ok(None);
    }
    let credential = resolve_unlocked_credential(state, cred_id).await?;
    Ok(current_totp(&credential))
}

/// `login_step` で `done` に達した段階ログインをハンドオフする。
async fn hand_off_step(
    state: &SharedState,
    peer: &PeerIdentity,
    id: Value,
    login_id: &str,
    ticket: Ticket,
    pending: Option<PendingExecutor>,
    done: DoneState,
) -> HandledRequest {
    let Some(pending) = pending else {
        return classified(id, ErrorCode::NotFound);
    };
    let key = ticket.key.clone();
    let launched = Launched {
        key: ticket.key,
        exclusive: ticket.exclusive,
        persist_cookies: ticket.persist_cookies,
        browser_started_at: ticket.browser_started_at,
        pending,
    };
    let gate = start_control(state, StartKey::Browser(key.clone())).await;
    let mut control = gate.lock().await;
    let handed = hand_off(state, &mut control, launched, done).await;
    drop(control);
    match handed {
        Ok(result) => {
            let session_id = result
                .get("session_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let fields = end_fields(login_id, &key, session_id);
            audit_stepwise(
                state,
                AuditPeer::Peer(peer),
                "stepwise_handoff",
                fields,
                "ok",
            )
            .await;
            success(id, result).with_audit_shared(false)
        }
        Err(error) => {
            // 登録に失敗した executor は register_login_browser が停止済みである。
            finish(
                state,
                login_id,
                &key,
                None,
                EndReason::Failed(error),
                AuditPeer::Peer(peer),
            )
            .await;
            classified(id, error)
        }
    }
}

/// executor へ `login_step` を 1 件送り、応答を待つ。TOTP コードを含む直列化結果は書き込み後に消去する。
async fn exchange_step(
    pending: &mut PendingExecutor,
    action: &StepAction,
    totp: Option<String>,
    wait: Duration,
) -> Result<ExecutorState, ExecutorFailure> {
    let id = pending.take_id();
    let request = ExecutorStepRequest {
        op: "login_step",
        id,
        action,
        totp,
    };
    let serialized = serde_json::to_vec(&request);
    drop(request);
    let mut line = serialized.map_err(|_| ErrorCode::Internal)?;
    line.push(b'\n');
    let written = timeout(EXECUTOR_OPERATION_TIMEOUT, pending.handle.write_line(&line)).await;
    line.zeroize();
    if !matches!(written, Ok(Ok(()))) {
        return Err(ErrorCode::Internal.into());
    }
    let response = timeout(wait, pending.handle.read_line())
        .await
        .map_err(|_| ErrorCode::Internal)?
        .map_err(|_| ErrorCode::Internal)?;
    if response.is_empty() {
        return Err(ErrorCode::Internal.into());
    }
    parse_state_response(&response, id)
}

/// ハンドオフ前の executor を停止する。`abort` では先に executor へ破棄を依頼する。
async fn stop_pending(mut pending: PendingExecutor, abort: bool) {
    if abort {
        let _ = exchange_step(
            &mut pending,
            &StepAction::Abort,
            None,
            EXECUTOR_OPERATION_TIMEOUT,
        )
        .await;
    }
    let id = pending.take_id();
    let executor = &mut pending.handle;
    let request = format!("{}\n", json!({ "op": "shutdown", "id": id }));
    let written = timeout(
        EXECUTOR_SHUTDOWN_TIMEOUT,
        executor.write_line(request.as_bytes()),
    )
    .await;
    if matches!(written, Ok(Ok(()))) {
        let _ = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, executor.read_line()).await;
    }
    if !wait_or_kill_executor(executor).await {
        kill_executor_handle(executor).await;
    }
}

/// 台帳から除いた段階ログインを終了する。処理中の step があれば、その完了を待ってから executor を回収する。
async fn end_entry(
    state: &SharedState,
    login_id: &str,
    entry: Entry,
    reason: EndReason,
    peer: AuditPeer<'_>,
) {
    let pending = entry.slot.lock().await.take();
    finish(state, login_id, &entry.key, pending, reason, peer).await;
}

/// executor を停止し、失敗として数える終了理由であればバックオフを記録し、終了を監査する。
async fn finish(
    state: &SharedState,
    login_id: &str,
    key: &BrowserKey,
    pending: Option<PendingExecutor>,
    reason: EndReason,
    peer: AuditPeer<'_>,
) {
    if let Some(pending) = pending {
        stop_pending(pending, matches!(reason, EndReason::Aborted)).await;
    }
    if reason.counts_as_failure() {
        let gate = start_control(state, StartKey::Browser(key.clone())).await;
        gate.lock().await.record_failure(Instant::now());
    }
    let fields = end_fields(login_id, key, None);
    audit_stepwise(state, peer, reason.audit_method(), fields, reason.outcome()).await;
}

fn end_fields(login_id: &str, key: &BrowserKey, session_id: Option<String>) -> AuditFields {
    AuditFields {
        cred_id: Some(key.cred_id.clone()),
        session_id,
        namespace: Some(key.namespace.clone()),
        login_id: Some(login_id.to_owned()),
        stepwise: Some(true),
        ..AuditFields::default()
    }
}

async fn audit_stepwise(
    state: &SharedState,
    peer: AuditPeer<'_>,
    method: &str,
    fields: AuditFields,
    outcome: &str,
) {
    let daemon = state.lock().await;
    if let Err(error) =
        append_audit(&daemon, peer, method.to_owned(), fields, outcome.to_owned()).await
    {
        eprintln!("tegatad: audit append failed: {error}");
    }
}

/// namespace（`None` は全体）の段階ログインをすべて終了する。`lock_vault` とデーモンの停止で用いる。
pub(crate) async fn terminate(state: &SharedState, namespace: Option<&str>, reason: EndReason) {
    let entries = state.lock().await.stepwise.take_namespace(namespace);
    end_all(state, entries, reason).await;
}

/// 失効した peer（principal）の段階ログインをすべて終了する。
pub(crate) async fn terminate_principal(state: &SharedState, principal: &str) {
    let entries = state.lock().await.stepwise.take_principal(principal);
    end_all(state, entries, EndReason::PeerRevoked).await;
}

/// 応答走査が secret を検出して差し替えた `pending` 応答の段階ログインを、SNAPSHOT_REJECTED と同等に終了する。
pub(crate) async fn end_leaked(state: &SharedState, login_id: &str, peer: &PeerIdentity) {
    let entry = state
        .lock()
        .await
        .stepwise
        .take_owned(login_id, &peer.principal());
    if let Some(entry) = entry {
        end_entry(
            state,
            login_id,
            entry,
            EndReason::Rejected,
            AuditPeer::Peer(peer),
        )
        .await;
    }
}

/// 段階ログインの method の `pending` 応答であれば、その login_id を返す。
pub(crate) fn pending_login_id(method: &str, result: Option<&Value>) -> Option<String> {
    if !matches!(method, "login_begin" | "login_step") {
        return None;
    }
    let result =
        result.filter(|result| result.get("state").and_then(Value::as_str) == Some("pending"))?;
    result
        .get("login_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

async fn end_all(state: &SharedState, entries: Vec<(String, Entry)>, reason: EndReason) {
    let mut tasks = JoinSet::new();
    for (login_id, entry) in entries {
        let state = state.clone();
        tasks.spawn(async move {
            end_entry(&state, &login_id, entry, reason, AuditPeer::System).await;
        });
    }
    while tasks.join_next().await.is_some() {}
}

/// 期限切れの段階ログインを 1 秒ごとに検出して終了する。
pub(crate) fn spawn_reaper(state: SharedState) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let expired = state.lock().await.stepwise.take_expired(Instant::now());
            for (login_id, entry) in expired {
                let state = state.clone();
                tokio::spawn(async move {
                    end_entry(
                        &state,
                        &login_id,
                        entry,
                        EndReason::Expired,
                        AuditPeer::System,
                    )
                    .await;
                });
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(params: Value) -> Result<StepParams, ErrorCode> {
        parse_step_params(&params)
    }

    fn valid(params: Value) -> StepParams {
        step(params.clone()).unwrap_or_else(|_| panic!("valid params were refused: {params}"))
    }

    fn fill_submit(values: &[&str]) -> Value {
        let fills = values
            .iter()
            .map(|value| json!({ "selector": "#f", "value": value }))
            .collect::<Vec<_>>();
        json!({
            "login_id": "x",
            "action": "fill_submit",
            "fills": fills,
            "submit": { "click": "#go" },
        })
    }

    #[test]
    fn flat_step_params_parse_into_actions() {
        let parsed = valid(json!({ "login_id": "x", "action": "click", "selector": "#next" }));
        assert_eq!(parsed.login_id, "x");
        assert_eq!(
            parsed.action,
            StepAction::Click {
                selector: "#next".to_owned()
            }
        );
        let parsed = valid(json!({ "login_id": "x", "action": "snapshot" }));
        assert_eq!(parsed.action, StepAction::Snapshot);
        let parsed = valid(json!({
            "login_id": "x",
            "action": "fill_submit",
            "fills": [{ "selector": "#p", "value": "{{password}}" }],
            "submit": { "press_enter": "#p" },
        }));
        assert_eq!(
            parsed.action,
            StepAction::FillSubmit {
                fills: vec![FillField {
                    selector: "#p".to_owned(),
                    value: "{{password}}".to_owned(),
                }],
                submit: Submit::PressEnter("#p".to_owned()),
            }
        );
    }

    #[test]
    fn secrets_outside_fill_submit_and_literal_values_are_refused() {
        for value in ["{{password}}", "{{totp}}", "literal"] {
            let params =
                json!({ "login_id": "x", "action": "fill", "selector": "#u", "value": value });
            assert!(step(params).is_err(), "{value}");
        }
        assert!(
            step(json!({ "login_id": "x", "action": "fill", "selector": "#u", "value": "{{username}}" }))
                .is_ok()
        );
        assert!(step(fill_submit(&["literal"])).is_err());
        assert!(step(fill_submit(&[])).is_err());
        assert!(step(fill_submit(&["{{username}}"; 4])).is_err());
        assert!(step(fill_submit(&["{{username}}", "{{password}}", "{{totp}}"])).is_ok());
    }

    #[test]
    fn malformed_step_params_are_refused() {
        for params in [
            json!({ "action": "snapshot" }),
            json!({ "login_id": "x" }),
            json!({ "login_id": "x", "action": "type", "selector": "#a" }),
            json!({ "login_id": "x", "action": "click" }),
            json!({ "login_id": "x", "action": "fill_submit", "fills": [{ "selector": "#p", "value": "{{password}}" }] }),
            json!({ "login_id": "x", "action": "fill_submit", "fills": [{ "selector": "#p", "value": "{{password}}" }], "submit": { "click": "#a", "press_enter": "#b" } }),
            json!({ "login_id": 1, "action": "snapshot" }),
        ] {
            assert!(step(params.clone()).is_err(), "{params}");
        }
    }

    #[test]
    fn only_totp_fill_submits_need_a_totp_code() {
        let needs = |params: Value| valid(params).action.needs_totp();
        assert!(needs(fill_submit(&["{{username}}", "{{totp}}"])));
        assert!(!needs(fill_submit(&["{{password}}"])));
        assert!(!needs(json!({ "login_id": "x", "action": "snapshot" })));
    }

    #[test]
    fn the_executor_request_is_flat_and_carries_the_totp_slot() {
        let action = StepAction::Click {
            selector: "#next".to_owned(),
        };
        let request = ExecutorStepRequest {
            op: "login_step",
            id: 3,
            action: &action,
            totp: None,
        };
        assert_eq!(
            serde_json::to_value(&request).expect("serialize"),
            json!({ "op": "login_step", "id": 3, "action": "click", "selector": "#next", "totp": null })
        );
    }

    #[test]
    fn executor_states_are_parsed_and_mismatched_ids_are_refused() {
        let pending = parse_state_response(
            r#"{"ok":true,"id":2,"state":"pending","snapshot":{"url":"u"}}"#,
            2,
        );
        assert!(matches!(pending, Ok(ExecutorState::Pending(snapshot)) if snapshot["url"] == "u"));
        let done = parse_state_response(
            r#"{"ok":true,"id":2,"state":"done","endpoint":"ws://127.0.0.1:9/x","target_id":"t","cookies":null,"steps_skipped":true}"#,
            2,
        );
        assert!(
            matches!(done, Ok(ExecutorState::Done(done)) if done.steps_skipped && done.cookies.is_none())
        );
        let rejected =
            parse_state_response(r#"{"ok":false,"id":2,"error":"SNAPSHOT_REJECTED"}"#, 2);
        assert!(
            matches!(rejected, Err(failure) if matches!(failure.code, ErrorCode::SnapshotRejected))
        );
        let missing = parse_state_response(
            r#"{"ok":false,"id":2,"error":"SELECTOR_NOT_FOUND","step":1}"#,
            2,
        );
        assert!(matches!(missing, Err(failure) if failure.step == Some(1)));
        let stale = parse_state_response(r#"{"ok":true,"id":1,"state":"aborted"}"#, 2);
        assert!(matches!(stale, Err(failure) if matches!(failure.code, ErrorCode::Internal)));
        let no_snapshot = parse_state_response(r#"{"ok":true,"id":2,"state":"pending"}"#, 2);
        assert!(no_snapshot.is_err());
    }

    #[test]
    fn audit_values_are_limited_to_known_actions_and_uuids() {
        let id = Uuid::new_v4().to_string();
        let params = json!({ "login_id": id, "action": "fill_submit" });
        assert_eq!(audit_action(&params).as_deref(), Some("fill_submit"));
        assert_eq!(audit_login_id(&params).as_deref(), Some(id.as_str()));
        let forged = json!({ "login_id": "not a uuid", "action": "anything" });
        assert_eq!(audit_action(&forged), None);
        assert_eq!(audit_login_id(&forged), None);
    }

    fn ledger_with(principal: &str, now: Instant) -> (Ledger, Slot) {
        let mut ledger = Ledger::new(Duration::from_secs(10), Duration::from_secs(100));
        let slot: Slot = Arc::new(Mutex::new(None));
        let key = BrowserKey::new(principal.to_owned(), "mock".to_owned(), "mock:a".to_owned());
        ledger.insert(
            "id".to_owned(),
            Entry::new(key, false, false, now, now, slot.clone()),
        );
        (ledger, slot)
    }

    #[test]
    fn a_login_id_is_bound_to_its_principal() {
        let now = Instant::now();
        let (mut ledger, _) = ledger_with("uid:1", now);
        assert!(matches!(ledger.claim("id", "uid:2", now), Claim::NotFound));
        assert!(matches!(
            ledger.claim("other", "uid:1", now),
            Claim::NotFound
        ));
        assert!(matches!(ledger.claim("id", "uid:1", now), Claim::Ready(_)));
    }

    #[test]
    fn idle_expiry_waits_for_the_step_in_flight() {
        let now = Instant::now();
        let (mut ledger, slot) = ledger_with("uid:1", now);
        assert!(matches!(ledger.claim("id", "uid:1", now), Claim::Ready(_)));
        let later = now + Duration::from_secs(20);
        assert!(ledger.take_expired(later).is_empty(), "a step is in flight");
        ledger.release("id", &slot, later);
        assert!(
            ledger
                .take_expired(later + Duration::from_secs(9))
                .is_empty()
        );
        assert_eq!(
            ledger.take_expired(later + Duration::from_secs(10)).len(),
            1
        );
    }

    #[test]
    fn the_absolute_limit_applies_even_while_a_step_is_in_flight() {
        let now = Instant::now();
        let (mut ledger, _) = ledger_with("uid:1", now);
        assert!(matches!(ledger.claim("id", "uid:1", now), Claim::Ready(_)));
        assert_eq!(ledger.take_expired(now + Duration::from_secs(100)).len(), 1);
    }

    #[test]
    fn an_expired_login_is_removed_when_a_step_arrives() {
        let now = Instant::now();
        let (mut ledger, _) = ledger_with("uid:1", now);
        let late = now + Duration::from_secs(11);
        assert!(matches!(
            ledger.claim("id", "uid:1", late),
            Claim::Expired(_)
        ));
        assert!(matches!(ledger.claim("id", "uid:1", late), Claim::NotFound));
    }

    #[test]
    fn the_step_after_the_limit_exhausts_the_login() {
        let now = Instant::now();
        let (mut ledger, slot) = ledger_with("uid:1", now);
        for _ in 0..MAX_STEPS {
            assert!(matches!(ledger.claim("id", "uid:1", now), Claim::Ready(_)));
            ledger.release("id", &slot, now);
        }
        assert!(matches!(
            ledger.claim("id", "uid:1", now),
            Claim::Exhausted(_)
        ));
        assert!(matches!(ledger.claim("id", "uid:1", now), Claim::NotFound));
    }

    #[test]
    fn principals_are_drained_selectively() {
        let now = Instant::now();
        let (mut ledger, _) = ledger_with("peer:a", now);
        assert!(ledger.take_owned("id", "peer:b").is_none());
        assert!(ledger.take_principal("peer:b").is_empty());
        assert_eq!(ledger.take_principal("peer:a").len(), 1);
    }

    #[test]
    fn only_pending_stepwise_answers_name_a_login_id() {
        let pending = json!({ "state": "pending", "login_id": "id", "snapshot": {} });
        let done = json!({ "state": "done", "session_id": "s" });
        assert_eq!(
            pending_login_id("login_step", Some(&pending)).as_deref(),
            Some("id")
        );
        assert_eq!(pending_login_id("login", Some(&pending)), None);
        assert_eq!(pending_login_id("login_begin", Some(&done)), None);
        assert_eq!(pending_login_id("login_begin", None), None);
    }

    #[test]
    fn namespaces_are_drained_selectively() {
        let now = Instant::now();
        let (mut ledger, _) = ledger_with("uid:1", now);
        assert!(ledger.take_namespace(Some("other")).is_empty());
        assert_eq!(ledger.take_namespace(Some("mock")).len(), 1);
        assert!(ledger.take_namespace(None).is_empty());
    }

    #[test]
    fn only_rejections_mismatches_bad_credentials_and_expiry_count_as_failures() {
        assert!(EndReason::Rejected.counts_as_failure());
        assert!(EndReason::Expired.counts_as_failure());
        assert!(EndReason::Failed(ErrorCode::FillMismatch).counts_as_failure());
        assert!(EndReason::Failed(ErrorCode::InvalidCredential).counts_as_failure());
        assert!(!EndReason::Aborted.counts_as_failure());
        assert!(!EndReason::Failed(ErrorCode::Internal).counts_as_failure());
        assert!(!EndReason::Failed(ErrorCode::RateLimited).counts_as_failure());
        assert!(!EndReason::LockVault.counts_as_failure());
        assert!(!EndReason::PeerRevoked.counts_as_failure());
    }
}
