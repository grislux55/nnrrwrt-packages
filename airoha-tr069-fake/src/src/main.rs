// SPDX-License-Identifier: GPL-2.0-only

use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant, SystemTime};

use airoha_tr069_fake::audit::{AuditLogger, DEFAULT_AUDIT_LOG_PATH};
use airoha_tr069_fake::config::FakeConfig;
use airoha_tr069_fake::crypto_tls::random_u64;
use airoha_tr069_fake::http::{ConnReqCreds, ConnectionRequestServer};
use airoha_tr069_fake::model::VirtualModel;
use airoha_tr069_fake::net_iso::InterfaceRuntime;
use airoha_tr069_fake::{
    apply_effects_to_config, apply_overlay_from_config, dump_sanitized_model_json,
    dump_sanitized_status_json, load_effective_cfg_and_model, load_raw_cfg_and_model,
    retry_wait_secs, run_cwmp_session, RuntimeEndpoints,
};
use serde_json::json;

const DEFAULT_CONFIG_PATH: &str = "/tmp/tr069-fake-runtime.json";
const DEFAULT_CONTROL_SOCK: &str = "/var/run/airoha-tr069-fake.sock";
/// Delay between a virtual reboot and its boot Inform.
const VIRTUAL_REBOOT_SECS: u64 = 15;
const DAD_HOLD_SECS: u64 = 10;
static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
    SIGNAL_STOP.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_shutdown_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            handle_shutdown_signal as *const () as libc::sighandler_t,
        );
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut cmd = "daemon";
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut sock_path = PathBuf::from(DEFAULT_CONTROL_SOCK);
    let mut pon_line_override: Option<String> = None;
    let mut param_name = String::new();
    let mut param_value = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" if i + 1 < args.len() => {
                config_path = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--sock" if i + 1 < args.len() => {
                sock_path = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--pon-line" if i + 1 < args.len() => {
                pon_line_override = Some(args[i + 1].clone());
                i += 2;
            }
            "--param" if i + 2 < args.len() => {
                param_name = args[i + 1].clone();
                param_value = args[i + 2].clone();
                i += 3;
            }
            other if !other.starts_with('-') => {
                cmd = other;
                i += 1;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let exit_code = match cmd {
        "daemon" => run_daemon(&config_path, &sock_path),
        "inform-once" => run_inform_once(&config_path),
        "reset-virtual" => run_reset_virtual(&config_path),
        "apply-overlay" => run_apply_overlay(&config_path),
        "set-param" => run_set_param(&config_path, &param_name, &param_value),
        "trigger-inform" => send_control_cmd(&sock_path, "TRIGGER_INFORM"),
        "status" => send_control_cmd(&sock_path, "STATUS"),
        "dump-status" => run_dump_status(&config_path, &sock_path, pon_line_override.as_deref()),
        "dump-model" => run_dump_model(&config_path),
        "clear-log" => run_clear_log(&config_path),
        _ => {
            eprintln!(
                "usage: airoha-tr069-fake [--config PATH] [--sock PATH] [--pon-line LINE] [daemon|inform-once|reset-virtual|apply-overlay|set-param --param NAME VAL|trigger-inform|status|dump-status|dump-model|clear-log]"
            );
            2
        }
    };
    std::process::exit(exit_code);
}

fn open_audit(cfg: &FakeConfig) -> AuditLogger {
    AuditLogger::new(if cfg.audit_log_path.starts_with("/tmp/") {
        cfg.audit_log_path.as_str()
    } else {
        DEFAULT_AUDIT_LOG_PATH
    })
}

fn run_inform_once(config_path: &Path) -> i32 {
    let (mut cfg, mut model) = match load_effective_cfg_and_model(config_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let audit = open_audit(&cfg);
    let rt = InterfaceRuntime::inspect(&cfg.tr069_ifname);
    match run_cwmp_session(&mut cfg, &mut model, &rt, &[], 0, &audit, None) {
        Ok(summary) => {
            println!("Inform completed: rpcs_handled={}", summary.rpcs_handled);
            0
        }
        Err(e) => {
            audit.record("ERROR", "cwmp", &format!("Inform failed: {e}"));
            eprintln!("error: {e}");
            1
        }
    }
}

fn run_reset_virtual(config_path: &Path) -> i32 {
    let (cfg, mut model) = match load_raw_cfg_and_model(config_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if let Err(e) = model.reset_virtual() {
        eprintln!("error: {e}");
        return 1;
    }
    let audit = open_audit(&cfg);
    audit.record("INFO", "model", "Virtual CWMP state reset to local template");
    println!("Virtual CWMP state reset");
    0
}

fn run_apply_overlay(config_path: &Path) -> i32 {
    let (cfg, _model) = match apply_overlay_from_config(config_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let audit = open_audit(&cfg);
    audit.record("INFO", "model", "Applied LuCI configuration overlay to virtual model");
    0
}

fn run_set_param(config_path: &Path, name: &str, value: &str) -> i32 {
    if name.is_empty() {
        eprintln!("--param NAME VALUE is required");
        return 2;
    }
    let (cfg, mut model) = match load_raw_cfg_and_model(config_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if let Err(e) = model.set_single_from_ui(name, value) {
        eprintln!("error: {e}");
        return 1;
    }
    let audit = open_audit(&cfg);
    audit.record("INFO", "model", &format!("UI updated {name}"));
    0
}

fn query_control_cmd(sock_path: &Path, cmd: &str) -> Result<String, String> {
    let mut stream = UnixStream::connect(sock_path)
        .map_err(|e| format!("control socket unavailable: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    writeln!(stream, "{cmd}").map_err(|e| format!("control write failed: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    reader
        .read_line(&mut resp)
        .map_err(|e| format!("control read failed: {e}"))?;
    if resp.is_empty() {
        return Err("empty control response".to_owned());
    }
    Ok(resp)
}

fn send_control_cmd(sock_path: &Path, cmd: &str) -> i32 {
    match query_control_cmd(sock_path, cmd) {
        Ok(resp) => {
            print!("{resp}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn run_dump_status(config_path: &Path, sock_path: &Path, pon_line: Option<&str>) -> i32 {
    let daemon_raw = if sock_path.exists() {
        query_control_cmd(sock_path, "STATUS").ok()
    } else {
        None
    };
    let json = dump_sanitized_status_json(
        config_path,
        pon_line,
        daemon_raw.as_deref(),
        Path::new("/tmp"),
    );
    println!("{json}");
    0
}

fn run_dump_model(config_path: &Path) -> i32 {
    let cfg = if config_path.exists() {
        match FakeConfig::load_json_file(config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        }
    } else {
        FakeConfig::default()
    };
    match dump_sanitized_model_json(&cfg) {
        Ok(json) => {
            println!("{json}");
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run_clear_log(config_path: &Path) -> i32 {
    let cfg = if config_path.exists() {
        FakeConfig::load_json_file(config_path).unwrap_or_default()
    } else {
        FakeConfig::default()
    };
    let audit = open_audit(&cfg);
    audit.clear();
    println!("{{\"ok\":true}}");
    0
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn effective_cfg(base: &FakeConfig, model: &VirtualModel) -> FakeConfig {
    let mut cfg = base.clone();
    apply_effects_to_config(&mut cfg, &model.current_management_effects(), None);
    cfg
}

/// Session retry state. As in stock, the count the Inform reports is kept apart from the
/// step on the wait ladder.
#[derive(Default)]
struct RetryState {
    /// Failed sessions since the last complete one, reported as RetryCount.
    count: u32,
    /// Retries waited for in a row.
    step: u32,
    /// When the next retry starts.
    at: Option<Instant>,
}

impl RetryState {
    fn fail(&mut self) -> Duration {
        self.count = self.count.saturating_add(1);
        self.step = self.step.saturating_add(1);
        let wait = Duration::from_secs(retry_wait_secs(self.step, random_u64()));
        self.at = Some(Instant::now() + wait);
        wait
    }

    /// The interface or the settings changed, so the cause of the failures may be gone:
    /// retry at once and start over with the shortest wait.
    fn hasten(&mut self) {
        if self.at.is_some() {
            self.step = 0;
            self.at = Some(Instant::now());
        }
    }
}

fn owe_event(owed: &mut Vec<&'static str>, event_code: &'static str) {
    if !owed.contains(&event_code) {
        owed.push(event_code);
    }
}

/// Owes "4 VALUE CHANGE" when the interface offers a ConnectionRequestURL or an address
/// that the last accepted Inform did not carry.
fn owe_value_change(
    owed: &mut Vec<&'static str>,
    reported: Option<&RuntimeEndpoints>,
    current: &RuntimeEndpoints,
) {
    if reported.is_some_and(|reported| current.differs_from(reported)) {
        owe_event(owed, "4 VALUE CHANGE");
    }
}

fn run_daemon(config_path: &Path, sock_path: &Path) -> i32 {
    let (mut base_cfg, mut model) = match load_raw_cfg_and_model(config_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("startup error: {e}");
            return 1;
        }
    };
    let mut cfg = effective_cfg(&base_cfg, &model);
    let audit = open_audit(&cfg);
    audit.record(
        "INFO",
        "lifecycle",
        &format!(
            "Started tr069-fake sandbox iface={} omci_sync={} conn_req={}",
            cfg.tr069_ifname, cfg.omci_sync, cfg.conn_req_enable
        ),
    );

    let manual_trigger = Arc::new(AtomicBool::new(false));
    let conn_req_trigger = Arc::new(AtomicBool::new(false));
    let conn_creds = Arc::new(Mutex::new(ConnReqCreds {
        path: cfg.conn_req_path.clone(),
        username: cfg.conn_req_username.clone(),
        password: cfg.conn_req_password.clone(),
    }));
    let stop_flag = Arc::new(AtomicBool::new(false));
    SIGNAL_STOP.store(false, Ordering::SeqCst);
    install_signal_handlers();

    let status_snapshot = Arc::new(Mutex::new(String::new()));
    let mut active_rt = InterfaceRuntime::inspect(&cfg.tr069_ifname);
    update_status_snapshot(&status_snapshot, &cfg, &active_rt, &model);
    let _sock_thread = start_control_socket(
        sock_path,
        Arc::clone(&manual_trigger),
        Arc::clone(&stop_flag),
        Arc::clone(&status_snapshot),
    );

    let mut conn_srv: Option<ConnectionRequestServer> =
        maybe_start_conn_req(&cfg, &active_rt, &conn_creds, &conn_req_trigger, &audit);

    // Events the next Inform carries beside the ones queued in the model.
    let mut owed_events: Vec<&'static str> = vec!["1 BOOT"];
    let mut retry = RetryState::default();
    let mut reboot_until: Option<Instant> = None;
    // What the last accepted Inform reported about the interface.
    let mut reported_endpoints: Option<RuntimeEndpoints> = None;
    let daemon_started = Instant::now();
    let mut last_inform = Instant::now();
    let mut last_poll_check = Instant::now();
    let mut last_cfg_mtime = file_mtime(config_path);
    let model_json_path = Path::new(&cfg.state_dir).join("model.json");
    let pending_json_path = Path::new(&cfg.state_dir).join("pending_events.json");
    let mut last_model_mtime = file_mtime(&model_json_path);
    let mut last_pending_mtime = file_mtime(&pending_json_path);

    while !stop_flag.load(Ordering::Relaxed) && !SIGNAL_STOP.load(Ordering::Relaxed) {
        if last_poll_check.elapsed() >= Duration::from_secs(5) {
            last_poll_check = Instant::now();
            let mut state_changed = false;

            let cur_cfg_mtime = file_mtime(config_path);
            if cur_cfg_mtime != last_cfg_mtime {
                last_cfg_mtime = cur_cfg_mtime;
                if let Ok((fresh_base, fresh_model)) = load_raw_cfg_and_model(config_path) {
                    let fresh_cfg = effective_cfg(&fresh_base, &fresh_model);
                    let conn_changed = fresh_cfg.conn_req_enable != cfg.conn_req_enable
                        || fresh_cfg.conn_req_port != cfg.conn_req_port
                        || fresh_cfg.conn_req_path != cfg.conn_req_path
                        || fresh_cfg.tr069_ifname != cfg.tr069_ifname;
                    base_cfg = fresh_base;
                    cfg = fresh_cfg;
                    model = fresh_model;
                    {
                        let mut g = conn_creds.lock().expect("conn_creds mutex poisoned");
                        g.path = cfg.conn_req_path.clone();
                        g.username = cfg.conn_req_username.clone();
                        g.password = cfg.conn_req_password.clone();
                    }
                    if conn_changed {
                        if let Some(old) = conn_srv.take() {
                            old.stop();
                        }
                        active_rt = InterfaceRuntime::inspect(&cfg.tr069_ifname);
                        conn_srv = maybe_start_conn_req(&cfg, &active_rt, &conn_creds, &conn_req_trigger, &audit);
                    }
                    retry.hasten();
                    state_changed = true;
                }
            } else {
                let cur_model_mtime = file_mtime(&model_json_path);
                let cur_pending_mtime = file_mtime(&pending_json_path);
                if cur_model_mtime != last_model_mtime || cur_pending_mtime != last_pending_mtime {
                    if let Ok(fresh_model) = VirtualModel::load_or_init(&base_cfg) {
                        model = fresh_model;
                        apply_effects_to_config(&mut cfg, &model.current_management_effects(), Some(&conn_creds));
                        state_changed = true;
                    }
                }
                last_model_mtime = cur_model_mtime;
                last_pending_mtime = cur_pending_mtime;
            }

            let fresh_rt = InterfaceRuntime::inspect(&cfg.tr069_ifname);
            if fresh_rt != active_rt {
                let gained_addr = (!fresh_rt.ipv4_addrs.is_empty() && active_rt.ipv4_addrs.is_empty())
                    || (!fresh_rt.ipv6_addrs.is_empty() && active_rt.ipv6_addrs.is_empty());
                active_rt = fresh_rt;
                if let Some(old) = conn_srv.take() {
                    old.stop();
                }
                conn_srv = maybe_start_conn_req(&cfg, &active_rt, &conn_creds, &conn_req_trigger, &audit);
                if gained_addr {
                    retry.hasten();
                }
                state_changed = true;
            }
            owe_value_change(
                &mut owed_events,
                reported_endpoints.as_ref(),
                &RuntimeEndpoints::of(&cfg, &active_rt),
            );

            if state_changed {
                update_status_snapshot(&status_snapshot, &cfg, &active_rt, &model);
            }
        }

        let manual = manual_trigger.swap(false, Ordering::SeqCst);
        let conn_req = conn_req_trigger.swap(false, Ordering::SeqCst);
        if conn_req {
            owe_event(&mut owed_events, "6 CONNECTION REQUEST");
        }
        if cfg.periodic_inform_enable
            && last_inform.elapsed() >= Duration::from_secs(cfg.periodic_inform_interval)
        {
            owe_event(&mut owed_events, "2 PERIODIC");
        }
        let now = Instant::now();
        let dad_hold = !active_rt.ipv6_tentative.is_empty()
            && daemon_started.elapsed() < Duration::from_secs(DAD_HOLD_SECS);
        let rebooting = reboot_until.is_some_and(|t| now < t);
        let undelivered = !owed_events.is_empty()
            || !model.pending.events.is_empty()
            || !model.pending.transfers.is_empty();
        let scheduled = match retry.at {
            // After a failed session only its retry timer starts the next one.
            Some(t) => now >= t,
            None => undelivered && !dad_hold && !rebooting,
        };

        // A manual trigger sends what is owed, or "2 PERIODIC" when nothing is.
        if manual || conn_req || scheduled {
            if let Ok(fresh_model) = VirtualModel::load_or_init(&base_cfg) {
                model = fresh_model;
                apply_effects_to_config(&mut cfg, &model.current_management_effects(), Some(&conn_creds));
            }
            let fresh_rt = InterfaceRuntime::inspect(&cfg.tr069_ifname);
            if fresh_rt != active_rt {
                active_rt = fresh_rt;
                if let Some(old) = conn_srv.take() {
                    old.stop();
                }
                conn_srv = maybe_start_conn_req(&cfg, &active_rt, &conn_creds, &conn_req_trigger, &audit);
            }
            // What the Inform of this session reports.
            let endpoints = RuntimeEndpoints::of(&cfg, &active_rt);
            owe_value_change(&mut owed_events, reported_endpoints.as_ref(), &endpoints);
            match run_cwmp_session(
                &mut cfg,
                &mut model,
                &active_rt,
                &owed_events,
                retry.count,
                &audit,
                Some(&conn_creds),
            ) {
                Ok(summary) => {
                    owed_events.clear();
                    retry = RetryState::default();
                    reboot_until = None;
                    last_inform = Instant::now();
                    reported_endpoints = Some(endpoints);
                    audit.record(
                        "INFO",
                        "cwmp",
                        &format!(
                            "Session finished rpcs={} virtual_reboot={}",
                            summary.rpcs_handled, summary.virtual_reboot_requested
                        ),
                    );
                    if summary.virtual_reboot_requested {
                        reboot_until =
                            Some(Instant::now() + Duration::from_secs(VIRTUAL_REBOOT_SECS));
                        audit.record(
                            "INFO",
                            "cwmp",
                            &format!("Virtual reboot: boot Inform in {VIRTUAL_REBOOT_SECS} s"),
                        );
                    }
                }
                Err(e) => {
                    if e.inform_accepted {
                        owed_events.clear();
                        last_inform = Instant::now();
                        reported_endpoints = Some(endpoints);
                    } else {
                        // A connection request event is not delivered again.
                        owed_events.retain(|ev| *ev != "6 CONNECTION REQUEST");
                    }
                    let owes_retry = e.inform_accepted
                        || !owed_events.is_empty()
                        || !model.pending.events.is_empty()
                        || !model.pending.transfers.is_empty();
                    if owes_retry || retry.at.is_some() {
                        let wait = retry.fail();
                        audit.record(
                            "WARN",
                            "cwmp",
                            &format!(
                                "Session error: {e}; retry {} in {} s",
                                retry.count,
                                wait.as_secs()
                            ),
                        );
                    } else {
                        // A trigger with nothing to deliver is not retried.
                        audit.record("WARN", "cwmp", &format!("Session error: {e}"));
                    }
                }
            }
            last_model_mtime = file_mtime(&model_json_path);
            last_pending_mtime = file_mtime(&pending_json_path);
            update_status_snapshot(&status_snapshot, &cfg, &active_rt, &model);
        }

        std::thread::sleep(Duration::from_millis(250));
    }
    stop_flag.store(true, Ordering::SeqCst);

    if let Some(old) = conn_srv.take() {
        old.stop();
    }
    let _ = fs::remove_file(sock_path);
    0
}

fn maybe_start_conn_req(
    cfg: &FakeConfig,
    rt: &InterfaceRuntime,
    creds: &Arc<Mutex<ConnReqCreds>>,
    trigger: &Arc<AtomicBool>,
    audit: &AuditLogger,
) -> Option<ConnectionRequestServer> {
    if !cfg.conn_req_enable {
        return None;
    }
    let addrs = rt.conn_req_bind_addrs(cfg.conn_req_port);
    if addrs.is_empty() {
        return None;
    }
    match ConnectionRequestServer::start(&addrs, Arc::clone(creds), Arc::clone(trigger), audit.clone()) {
        Ok(srv) => {
            audit.record(
                "INFO",
                "conn_req",
                &format!("Listening for ConnectionRequest on {:?}", srv.bound_addrs),
            );
            Some(srv)
        }
        Err(e) => {
            audit.record("WARN", "conn_req", &format!("Failed to bind ConnectionRequest: {e}"));
            None
        }
    }
}

fn update_status_snapshot(
    dst: &Arc<Mutex<String>>,
    cfg: &FakeConfig,
    rt: &InterfaceRuntime,
    model: &VirtualModel,
) {
    let ipv4_addrs: Vec<String> = rt.ipv4_addrs.iter().map(ToString::to_string).collect();
    let ipv6_addrs: Vec<String> = rt.ipv6_addrs.iter().map(ToString::to_string).collect();
    let s = json!({
        "acs_url": cfg.acs_url,
        "ifname": rt.ifname,
        "ipv4_addrs": ipv4_addrs,
        "ipv6_addrs": ipv6_addrs,
        "periodic_inform_interval": cfg.periodic_inform_interval,
        "running": true,
        "software_version": model
            .get_value("InternetGatewayDevice.DeviceInfo.SoftwareVersion")
            .unwrap_or(""),
        "virtual_boot_epoch": model.pending.virtual_boot_epoch,
    })
    .to_string();
    *dst.lock().expect("status poisoned") = s;
}

fn start_control_socket(
    sock_path: &Path,
    trigger_inform: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    status_snapshot: Arc<Mutex<String>>,
) -> Option<std::thread::JoinHandle<()>> {
    if let Some(parent) = sock_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::remove_file(sock_path);
    let listener = UnixListener::bind(sock_path).ok()?;
    let _ = fs::set_permissions(sock_path, fs::Permissions::from_mode(0o600));
    let _ = listener.set_nonblocking(true);
    Some(std::thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) && !SIGNAL_STOP.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    let mut line = String::new();
                    let mut reader = BufReader::new(&stream);
                    if reader.read_line(&mut line).is_ok() {
                        match line.trim() {
                            "TRIGGER_INFORM" => {
                                trigger_inform.store(true, Ordering::SeqCst);
                                let _ = writeln!(stream, "{{\"ok\":true,\"triggered\":true}}");
                            }
                            "STATUS" => {
                                let snap = status_snapshot.lock().expect("status poisoned").clone();
                                let _ = writeln!(stream, "{snap}");
                            }
                            _ => {
                                let _ = writeln!(stream, "{{\"error\":\"unknown command\"}}");
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    }))
}
