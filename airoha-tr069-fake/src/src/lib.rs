// SPDX-License-Identifier: GPL-2.0-only

pub mod audit;
pub mod config;
pub mod crypto_tls;
pub mod cwmp;
pub mod http;
pub mod model;
pub mod net_iso;

use std::fmt;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

use serde_json::{json, Map as JsonMap, Value as JsonValue};

use audit::AuditLogger;
use config::FakeConfig;
use crypto_tls::random_u64;
use cwmp::{
    build_fault, build_inform, build_transfer_complete, dispatch_rpc, parse_cwmp_envelope,
    CwmpMessage,
};
use http::{AcsHttpClient, ConnReqCreds};
pub use model::dump_sanitized_model_json;
use model::{CwmpFault, ManagementEffects, PendingEvent, VirtualModel};
use net_iso::InterfaceRuntime;

/// Consecutive unparsable ACS replies after which a session is abandoned.
const MAX_MALFORMED_REPLIES: u32 = 3;
const RETRY_MIN_WAIT_SECS: u64 = 5;
const RETRY_MAX_STEPS: u32 = 10;

/// Seconds to wait before the `step`-th session retry in a row. Stock retry_later waits
/// m * k^(n-1) seconds plus a random amount below that, with m = 5 and k = 2, and holds
/// n at 10: 5 to 10 s at first, 2560 to 5120 s from the tenth retry on.
pub fn retry_wait_secs(step: u32, random: u64) -> u64 {
    let base = RETRY_MIN_WAIT_SECS << (step.clamp(1, RETRY_MAX_STEPS) - 1);
    base + random % base
}

/// What an Inform reports about the management interface. A field is None while the
/// interface offers no value; the data model then keeps the last one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeEndpoints {
    /// Empty while the connection request listener is disabled.
    pub conn_req_url: Option<String>,
    pub ipv4: Option<Ipv4Addr>,
}

impl RuntimeEndpoints {
    pub fn of(cfg: &FakeConfig, rt: &InterfaceRuntime) -> Self {
        let conn_req_url = if cfg.conn_req_enable {
            rt.conn_req_bind_addrs(cfg.conn_req_port)
                .first()
                .map(|sa| format!("http://{}{}", sa, cfg.conn_req_path))
        } else {
            Some(String::new())
        };
        Self {
            conn_req_url,
            ipv4: rt.ipv4_addrs.first().copied(),
        }
    }

    /// True when an Inform sent now carries a value that `reported` did not.
    pub fn differs_from(&self, reported: &Self) -> bool {
        (self.conn_req_url.is_some() && self.conn_req_url != reported.conn_req_url)
            || (self.ipv4.is_some() && self.ipv4 != reported.ipv4)
    }
}

pub fn load_raw_cfg_and_model(config_path: &Path) -> Result<(FakeConfig, VirtualModel), String> {
    let cfg = if config_path.exists() {
        FakeConfig::load_json_file(config_path)?
    } else {
        FakeConfig::default()
    };
    let model = VirtualModel::load_or_init(&cfg)?;
    Ok((cfg, model))
}

pub fn load_effective_cfg_and_model(
    config_path: &Path,
) -> Result<(FakeConfig, VirtualModel), String> {
    let (mut cfg, model) = load_raw_cfg_and_model(config_path)?;
    apply_effects_to_config(&mut cfg, &model.current_management_effects(), None);
    Ok((cfg, model))
}

pub fn apply_overlay_from_config(config_path: &Path) -> Result<(FakeConfig, VirtualModel), String> {
    let (cfg, mut model) = load_raw_cfg_and_model(config_path)?;
    model.apply_config_overlay(&cfg)?;
    Ok((cfg, model))
}

fn redact_json_secrets(val: JsonValue) -> JsonValue {
    match val {
        JsonValue::Object(map) => {
            let mut out = JsonMap::new();
            for (k, v) in map {
                let lower = k.to_ascii_lowercase();
                let is_secret = lower.contains("password") || lower.contains("secret");
                let next_v = match v {
                    JsonValue::String(s) if is_secret => {
                        JsonValue::String(if s.is_empty() { String::new() } else { "***".to_owned() })
                    }
                    other => redact_json_secrets(other),
                };
                out.insert(k, next_v);
            }
            JsonValue::Object(out)
        }
        JsonValue::Array(arr) => JsonValue::Array(arr.into_iter().map(redact_json_secrets).collect()),
        other => other,
    }
}

fn is_valid_pon_line(line: &str) -> bool {
    !line.is_empty()
        && line
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Builds a read-only `{"daemon":...,"omci":...,"pending":...}` JSON snapshot with OMCI
/// passwords redacted and zero filesystem writes.
pub fn dump_sanitized_status_json(
    config_path: &Path,
    pon_line_override: Option<&str>,
    daemon_status_raw: Option<&str>,
    omci_dir: &Path,
) -> String {
    let cfg = if config_path.exists() {
        FakeConfig::load_json_file(config_path).unwrap_or_default()
    } else {
        FakeConfig::default()
    };
    let daemon_val = daemon_status_raw
        .and_then(|s| serde_json::from_str::<JsonValue>(s).ok())
        .filter(|v| v.as_object().is_some())
        .map(redact_json_secrets)
        .unwrap_or_else(|| JsonValue::Object(JsonMap::new()));

    let chosen_line = pon_line_override
        .filter(|s| is_valid_pon_line(s))
        .or_else(|| {
            if is_valid_pon_line(&cfg.pon_line) {
                Some(cfg.pon_line.as_str())
            } else {
                None
            }
        })
        .unwrap_or("line0");
    let omci_path = omci_dir.join(format!("airoha-pond-tr069.{chosen_line}.json"));
    let omci_val = fs::read_to_string(&omci_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<JsonValue>(&raw).ok())
        .map(redact_json_secrets)
        .unwrap_or(JsonValue::Null);

    let pending_path = Path::new(&cfg.state_dir).join("pending_events.json");
    let pending_val = fs::read_to_string(&pending_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<JsonValue>(&raw).ok())
        .map(redact_json_secrets)
        .unwrap_or(JsonValue::Null);

    json!({
        "daemon": daemon_val,
        "omci": omci_val,
        "pending": pending_val,
    })
    .to_string()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionSummary {
    pub rpcs_handled: usize,
    pub virtual_reboot_requested: bool,
    pub effects_applied: ManagementEffects,
}

/// A failed session. `inform_accepted` tells whether the ACS took the Inform, and with it
/// the events of the session, before the failure.
#[derive(Debug)]
pub struct SessionError {
    pub inform_accepted: bool,
    pub cause: io::Error,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}

impl std::error::Error for SessionError {}

pub fn apply_effects_to_config(
    cfg: &mut FakeConfig,
    eff: &ManagementEffects,
    conn_creds: Option<&Arc<Mutex<ConnReqCreds>>>,
) {
    if let Some(v) = &eff.acs_url {
        cfg.acs_url = v.clone();
    }
    if let Some(v) = &eff.acs_username {
        cfg.acs_username = v.clone();
    }
    if let Some(v) = &eff.acs_password {
        cfg.acs_password = v.clone();
    }
    if let Some(v) = eff.periodic_inform_enable {
        cfg.periodic_inform_enable = v;
    }
    if let Some(v) = eff.periodic_inform_interval {
        cfg.periodic_inform_interval = v;
    }
    if let Some(v) = &eff.conn_req_username {
        cfg.conn_req_username = v.clone();
    }
    if let Some(v) = &eff.conn_req_password {
        cfg.conn_req_password = v.clone();
    }
    if let Some(lock) = conn_creds {
        let mut g = lock.lock().expect("conn_creds mutex poisoned");
        g.username = cfg.conn_req_username.clone();
        g.password = cfg.conn_req_password.clone();
    }
}

/// Runs one CWMP session: the Inform, the queued TransferComplete calls, then the requests
/// of the ACS. `retry_count` is the number of failed sessions since the last complete one.
pub fn run_cwmp_session(
    cfg: &mut FakeConfig,
    model: &mut VirtualModel,
    rt: &InterfaceRuntime,
    extra_events: &[&str],
    retry_count: u32,
    audit: &AuditLogger,
    conn_creds: Option<&Arc<Mutex<ConnReqCreds>>>,
) -> Result<SessionSummary, SessionError> {
    // Every request of a session carries the same cwmp:ID, a random 31-bit decimal as in
    // the stock client.
    let session_id = (random_u64() >> 33).to_string();
    let mut client =
        send_inform(cfg, model, rt, extra_events, retry_count, &session_id, audit).map_err(
            |cause| SessionError {
                inform_accepted: false,
                cause,
            },
        )?;
    // The ACS has the events. A state file that cannot be written fails the session, so
    // the retry wait bounds how often the events on flash go out again.
    model
        .consume_pending_events()
        .map_err(|e| io::Error::other(format!("cannot save pending events: {e}")))
        .and_then(|()| serve_acs(&mut client, cfg, model, &session_id, audit, conn_creds))
        .map_err(|cause| SessionError {
            inform_accepted: true,
            cause,
        })
}

/// A SOAP Fault in a 2xx reply to a CPE request: the ACS refused the request.
fn acs_fault(body: &[u8]) -> Option<String> {
    let env = parse_cwmp_envelope(&String::from_utf8_lossy(body)).ok()?;
    match env.message {
        CwmpMessage::Fault { code, message } => Some(format!("{code} {message}")),
        _ => None,
    }
}

/// Connects to the ACS and delivers the Inform. It carries the queued events,
/// `extra_events` and "7 TRANSFER COMPLETE" for a queued transfer, or "2 PERIODIC" when
/// there is none of them.
fn send_inform(
    cfg: &FakeConfig,
    model: &mut VirtualModel,
    rt: &InterfaceRuntime,
    extra_events: &[&str],
    retry_count: u32,
    session_id: &str,
    audit: &AuditLogger,
) -> io::Result<AcsHttpClient> {
    if cfg.acs_url.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACS URL is empty",
        ));
    }
    let mut client = AcsHttpClient::new(
        &cfg.acs_url,
        &cfg.acs_username,
        &cfg.acs_password,
        cfg.insecure_tls,
        rt.clone(),
        audit.clone(),
    )?;

    let mut events = model.pending.events.clone();
    let transfer_event = (!model.pending.transfers.is_empty()).then_some("7 TRANSFER COMPLETE");
    for ev in extra_events.iter().copied().chain(transfer_event) {
        if !events.iter().any(|e| e.event_code == ev) {
            events.push(PendingEvent {
                event_code: ev.to_owned(),
                command_key: String::new(),
            });
        }
    }
    if events.is_empty() {
        events.push(PendingEvent {
            event_code: "2 PERIODIC".to_owned(),
            command_key: String::new(),
        });
    }

    let endpoints = RuntimeEndpoints::of(cfg, rt);
    let _ = model.update_runtime_endpoints(endpoints.conn_req_url.as_deref(), endpoints.ipv4);

    let inform_xml = build_inform(
        session_id,
        model,
        &events,
        endpoints.conn_req_url.as_deref().unwrap_or_default(),
        retry_count,
    );
    audit.record(
        "INFO",
        "cwmp",
        &format!(
            "Sending Inform to {} events={:?} retry_count={retry_count}",
            cfg.acs_url,
            events.iter().map(|e| e.event_code.as_str()).collect::<Vec<_>>()
        ),
    );
    let resp = client.post_cwmp(&inform_xml, Some("Inform"))?;
    if !(200..300).contains(&resp.status) {
        return Err(io::Error::other(format!(
            "ACS rejected Inform with HTTP {}",
            resp.status
        )));
    }
    if let Some(fault) = acs_fault(&resp.body) {
        return Err(io::Error::other(format!(
            "ACS answered Inform with fault {fault}"
        )));
    }
    Ok(client)
}

/// Delivers the queued TransferComplete calls, then answers the requests of the ACS until
/// it ends the session.
fn serve_acs(
    client: &mut AcsHttpClient,
    cfg: &mut FakeConfig,
    model: &mut VirtualModel,
    session_id: &str,
    audit: &AuditLogger,
    conn_creds: Option<&Arc<Mutex<ConnReqCreds>>>,
) -> io::Result<SessionSummary> {
    while let Some(tr) = model.pending.transfers.first().cloned() {
        let tc_xml = build_transfer_complete(session_id, &tr);
        audit.record(
            "INFO",
            "cwmp",
            &format!("Sending TransferComplete command_key={}", tr.command_key),
        );
        let tc_resp = client.post_cwmp(&tc_xml, Some("TransferComplete"))?;
        if !(200..300).contains(&tc_resp.status) {
            return Err(io::Error::other(format!(
                "ACS rejected TransferComplete with HTTP {}",
                tc_resp.status
            )));
        }
        if let Some(fault) = acs_fault(&tc_resp.body) {
            return Err(io::Error::other(format!(
                "ACS answered TransferComplete with fault {fault}"
            )));
        }
        model
            .consume_pending_transfer()
            .map_err(|e| io::Error::other(format!("cannot save pending transfers: {e}")))?;
    }

    let mut summary = SessionSummary::default();
    let mut next_body = String::new();
    let mut malformed_replies = 0u32;
    // The ACS ends the session with 204 or an empty body; the number of RPCs is its choice.
    loop {
        let acs_resp = client.post_cwmp(&next_body, None)?;
        if acs_resp.status == 204
            || ((200..300).contains(&acs_resp.status) && acs_resp.body.is_empty())
        {
            break;
        }
        if acs_resp.status < 200 || acs_resp.status >= 300 {
            return Err(io::Error::other(format!(
                "ACS returned HTTP {} during CWMP session",
                acs_resp.status
            )));
        }
        let acs_xml = String::from_utf8_lossy(&acs_resp.body).to_string();
        audit.record("DEBUG", "cwmp_rx", &acs_xml);
        let env = match parse_cwmp_envelope(&acs_xml) {
            Ok(e) => e,
            Err(err) => {
                audit.record("WARN", "cwmp", &format!("Malformed ACS SOAP XML: {err}"));
                malformed_replies += 1;
                if malformed_replies >= MAX_MALFORMED_REPLIES {
                    return Err(io::Error::other(format!(
                        "ACS sent {malformed_replies} malformed SOAP replies in a row"
                    )));
                }
                next_body = build_fault(None, &CwmpFault::simple(9003, err));
                continue;
            }
        };
        malformed_replies = 0;
        if let CwmpMessage::Unsupported { method } = &env.message {
            audit.record(
                "WARN",
                "cwmp",
                &format!("ACS sent unsupported CWMP element {method}"),
            );
        }
        summary.rpcs_handled += 1;
        let (reply_opt, eff, reboot_req) = dispatch_rpc(&env, model, cfg);
        apply_effects_to_config(cfg, &eff, conn_creds);
        merge_effects(&mut summary.effects_applied, &eff);
        if reboot_req {
            summary.virtual_reboot_requested = true;
        }
        match reply_opt {
            Some(reply) => {
                audit.record("DEBUG", "cwmp_tx", &reply);
                next_body = reply;
            }
            None => break,
        }
    }
    Ok(summary)
}

fn merge_effects(dst: &mut ManagementEffects, src: &ManagementEffects) {
    if src.acs_url.is_some() {
        dst.acs_url = src.acs_url.clone();
    }
    if src.acs_username.is_some() {
        dst.acs_username = src.acs_username.clone();
    }
    if src.acs_password.is_some() {
        dst.acs_password = src.acs_password.clone();
    }
    if src.periodic_inform_enable.is_some() {
        dst.periodic_inform_enable = src.periodic_inform_enable;
    }
    if src.periodic_inform_interval.is_some() {
        dst.periodic_inform_interval = src.periodic_inform_interval;
    }
    if src.conn_req_username.is_some() {
        dst.conn_req_username = src.conn_req_username.clone();
    }
    if src.conn_req_password.is_some() {
        dst.conn_req_password = src.conn_req_password.clone();
    }
}

pub fn trigger_flag_new() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}
