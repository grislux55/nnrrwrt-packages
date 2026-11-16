// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use airoha_tr069_fake::audit::{is_sensitive_param_name, redact_secrets, AuditLogger};
use airoha_tr069_fake::config::{parse_omci_export_json, DownloadMapping, FakeConfig};
use airoha_tr069_fake::crypto_tls::{md5_hex, sha256_hex};
use airoha_tr069_fake::cwmp::{dispatch_rpc, parse_cwmp_envelope, xml_unescape, CwmpMessage};
use airoha_tr069_fake::http::{
    build_digest_authorization, parse_digest_challenge, read_http_response,
    verify_digest_authorization, ConnReqCreds, ConnectionRequestServer, MAX_HTTP_BODY_BYTES,
};
use airoha_tr069_fake::model::{format_unix_timestamp, VirtualBootMark, VirtualModel};
use airoha_tr069_fake::net_iso::{
    build_dns_query, parse_dns_response, query_dns_server_addr, InterfaceRuntime,
};
use airoha_tr069_fake::{
    apply_effects_to_config, apply_overlay_from_config, dump_sanitized_model_json,
    dump_sanitized_status_json, load_effective_cfg_and_model, retry_wait_secs,
    run_cwmp_session, RuntimeEndpoints,
};
use serde_json::Value as JsonValue;

fn temp_dir(name: &str) -> PathBuf {
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from(format!("/tmp/tr069-fake-test-{name}-{}-{ns}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_omci_manual_priority_merge() {
    let omci_json = r#"{
      "protocol_version": 1,
      "line": "line0",
      "updated_at_ms": 1700000000000,
      "management_vlan": 46,
      "ipv4_hosts": [{
        "entity_id": 1,
        "mac_address": "02:00:00:00:00:46",
        "ip_options": 1,
        "ip_address": "0.0.0.0",
        "mask": "0.0.0.0",
        "gateway": "0.0.0.0",
        "primary_dns": "0.0.0.0"
      }],
      "ipv6_hosts": [{
        "entity_id": 1,
        "mac_address": "02:00:00:00:00:46",
        "ip_options": 3,
        "ipv6_address": "::",
        "gateway": "::",
        "primary_dns": "::"
      }],
      "tr069_servers": [{
        "entity_id": 1,
        "admin_state": true,
        "acs_url": "http://omci-acs.example.invalid:9090/acs",
        "acs_username": "omci_user",
        "acs_password": "omci_secret_value"
      }]
    }"#;
    let omci = parse_omci_export_json(omci_json).unwrap();
    assert_eq!(omci.management_vlan, Some(46));
    assert_eq!(omci.ipv4_mode, "dhcp");
    assert_eq!(omci.ipv6_mode, "dhcpv6");

    // Manual config takes precedence when set
    let mut cfg = FakeConfig::default();
    cfg.vlan_id = Some(88);
    cfg.acs_url = "http://manual-acs.example.invalid:7547/cwmp".to_owned();
    cfg.acs_username = "manual_user".to_owned();
    cfg.apply_omci_fallback(&omci);
    assert_eq!(cfg.vlan_id, Some(88));
    assert_eq!(cfg.acs_url, "http://manual-acs.example.invalid:7547/cwmp");
    assert_eq!(cfg.acs_username, "manual_user");
    assert_eq!(cfg.acs_password, "omci_secret_value");
    assert_eq!(cfg.macaddr, "02:00:00:00:00:46");
}

#[test]
fn test_virtual_model_persistence_rpcs_and_reset() {
    let dir = temp_dir("model");
    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.software_version = "NNRRWrt-1.0.0".to_owned();
    cfg.download_mappings.push(DownloadMapping {
        pattern: "fw-v2.0.0.bin".to_owned(),
        file_type: "1 Firmware Upgrade Image".to_owned(),
        target_version: "NNRRWrt-2.0.0".to_owned(),
    });

    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    assert_eq!(
        model.get_value("InternetGatewayDevice.DeviceInfo.SoftwareVersion"),
        Some("NNRRWrt-1.0.0")
    );

    // SetParameterValues updates model & management side-effects
    let set_xml = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>42</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:SetParameterValues><ParameterList><ParameterValueStruct><Name>InternetGatewayDevice.ManagementServer.PeriodicInformInterval</Name><Value xsi:type="xsd:unsignedInt">120</Value></ParameterValueStruct><ParameterValueStruct><Name>InternetGatewayDevice.DeviceInfo.ProvisioningCode</Name><Value xsi:type="xsd:string">PROV-TEST</Value></ParameterValueStruct></ParameterList><ParameterKey>key-42</ParameterKey></cwmp:SetParameterValues></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    let env = parse_cwmp_envelope(set_xml).unwrap();
    let (reply, eff, _) = dispatch_rpc(&env, &mut model, &cfg);
    assert!(reply.unwrap().contains("SetParameterValuesResponse"));
    assert_eq!(eff.periodic_inform_interval, Some(120));

    // Invalid / read-only parameter produces Fault 9008 / 9005
    let bad_set = model.set_parameter_values(
        &[(
            "InternetGatewayDevice.DeviceInfo.SerialNumber".to_owned(),
            "OVERRIDE".to_owned(),
            None,
        )],
        "bad",
    );
    assert!(bad_set.is_err());
    assert_eq!(bad_set.unwrap_err().param_faults[0].1, 9008);

    // AddObject & DeleteObject
    let inst = model
        .add_object("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.", "k-add")
        .unwrap();
    assert!(inst >= 2);
    assert!(model
        .get_value(&format!(
            "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{inst}.Enable"
        ))
        .is_some());
    model
        .delete_object(
            &format!("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{inst}."),
            "k-del",
        )
        .unwrap();

    // Virtual Download: unmapped returns 9010 fault, mapped updates SoftwareVersion
    let fail_dl = model.handle_download(
        "dl-bad",
        "1 Firmware Upgrade Image",
        "http://acs.example.invalid/unknown.bin",
        &cfg.download_mappings,
    );
    assert_eq!(fail_dl.unwrap_err().code, 9010);

    let ok_dl = model
        .handle_download(
            "dl-ok",
            "1 Firmware Upgrade Image",
            "http://acs.example.invalid/images/fw-v2.0.0.bin",
            &cfg.download_mappings,
        )
        .unwrap();
    assert_eq!(ok_dl.fault_code, 0);

    // Virtual Reboot increments boot epoch & queues M Reboot + 1 BOOT without touching host OS
    model.handle_reboot("rb-1").unwrap();
    assert!(model.pending.virtual_boot_epoch >= 2);

    // Reload from disk verifies persistence
    let reloaded = VirtualModel::load_or_init(&cfg).unwrap();
    assert_eq!(
        reloaded.get_value("InternetGatewayDevice.DeviceInfo.SoftwareVersion"),
        Some("NNRRWrt-2.0.0")
    );
    assert_eq!(
        reloaded.get_value("InternetGatewayDevice.DeviceInfo.ProvisioningCode"),
        Some("PROV-TEST")
    );
    assert_eq!(
        reloaded.get_value("InternetGatewayDevice.ManagementServer.PeriodicInformInterval"),
        Some("120")
    );
    assert!(reloaded.pending.events.iter().any(|e| e.event_code == "M Reboot"));

    // Standalone reset restores template
    let mut reset_vm = reloaded;
    reset_vm.reset_virtual().unwrap();
    assert_eq!(
        reset_vm.get_value("InternetGatewayDevice.DeviceInfo.SoftwareVersion"),
        Some("NNRRWrt-1.0.0")
    );
    assert_eq!(
        reset_vm.get_value("InternetGatewayDevice.DeviceInfo.ProvisioningCode"),
        Some("")
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_audit_log_redaction_and_tmp_ring_bounds() {
    let dir = temp_dir("audit");
    let log_path = dir.join("tr069-fake.log");
    let logger = AuditLogger::with_limits(&log_path, 3, 2048);
    logger.record(
        "DEBUG",
        "http",
        "Authorization: Digest username=\"cpe\", realm=\"test\", response=\"deadbeef1234\" acs_password=secretpw",
    );
    logger.record(
        "DEBUG",
        "cwmp",
        "<Name>InternetGatewayDevice.ManagementServer.Password</Name><Value xsi:type=\"xsd:string\">topsecret</Value>",
    );
    logger.record("INFO", "cwmp", "line3");
    logger.record("INFO", "cwmp", "line4");

    let snap = logger.snapshot();
    assert_eq!(snap.len(), 3);
    let joined = snap.join("\n");
    assert!(!joined.contains("topsecret"));
    assert!(!joined.contains("secretpw"));
    assert!(!joined.contains("deadbeef1234"));
    assert!(joined.contains("***"));
    let mode = fs::metadata(&log_path).expect("audit log metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let redacted = redact_secrets("Authorization: Basic dXNlcjpwYXNz password='abc'");
    assert!(!redacted.contains("dXNlcjpwYXNz"));
    assert!(!redacted.contains("'abc'"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_redaction_hides_wlan_keys_and_subscriber_identities() {
    for name in [
        "InternetGatewayDevice.ManagementServer.Password",
        "InternetGatewayDevice.ManagementServer.ConnectionRequestPassword",
        "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
        "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase",
        "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.PreSharedKey",
        "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WEPKey.1.WEPKey",
        "InternetGatewayDevice.X_CT-COM_UserInfo.UserName",
        "InternetGatewayDevice.X_CT-COM_UserInfo.UserId",
        "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username",
        "Device.PPP.Interface.1.Username",
        "Device.WiFi.AccessPoint.1.Security.SAEPassphrase",
    ] {
        assert!(is_sensitive_param_name(name), "{name}");
    }
    for name in [
        "InternetGatewayDevice.ManagementServer.Username",
        "InternetGatewayDevice.ManagementServer.ConnectionRequestUsername",
        "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WEPKeyIndex",
        "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.AssociatedDeviceMACAddress",
        "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
        "InternetGatewayDevice.",
    ] {
        assert!(!is_sensitive_param_name(name), "{name}");
    }

    let value_struct = |name: &str, value: &str| {
        format!("<ParameterValueStruct>\n<Name>{name}</Name>\n<Value xsi:type=\"xsd:string\">{value}</Value>\n</ParameterValueStruct>\n")
    };
    let body = [
        value_struct("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.KeyPassphrase", "wlan-passphrase-1"),
        value_struct("InternetGatewayDevice.X_CT-COM_UserInfo.UserName", "loid-0001"),
        value_struct("InternetGatewayDevice.X_CT-COM_UserInfo.UserId", "loid-pass-2"),
        value_struct("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username", "ppp-account-3"),
        value_struct("InternetGatewayDevice.ManagementServer.Username", "acs-user-4"),
        // A sensitive name without a value of its own leaves the next value alone.
        "<ParameterInfoStruct>\n<Name>InternetGatewayDevice.ManagementServer.Password</Name>\n<Writable>1</Writable>\n</ParameterInfoStruct>\n".to_owned(),
        value_struct("InternetGatewayDevice.DeviceInfo.SoftwareVersion", "fw-version-5"),
        "<ParameterValueStruct>\n<Name>InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WEPKey.1.WEPKey</Name>\n<Value xsi:type=\"xsd:string\"/>\n</ParameterValueStruct>\n".to_owned(),
        value_struct("InternetGatewayDevice.DeviceInfo.HardwareVersion", "hw-version-6"),
    ]
    .concat();
    let redacted = redact_secrets(&body);
    for hidden in ["wlan-passphrase-1", "loid-0001", "loid-pass-2", "ppp-account-3"] {
        assert!(!redacted.contains(hidden), "{hidden} left in: {redacted}");
    }
    for kept in ["acs-user-4", "fw-version-5", "hw-version-6"] {
        assert!(redacted.contains(kept), "{kept} missing in: {redacted}");
    }
    assert_eq!(redacted.matches("***</Value>").count(), 4);

    // A value that holds markup in CDATA, and one cut off before its end tag.
    let cdata = redact_secrets(
        "<Name>InternetGatewayDevice.X_CT-COM_UserInfo.UserId</Name>\n<Value><![CDATA[cdata<Name>pass-7]]></Value>\n<Name>InternetGatewayDevice.DeviceInfo.ProductClass</Name>\n<Value>class-8</Value>",
    );
    assert!(!cdata.contains("pass-7"), "{cdata}");
    assert!(cdata.contains("class-8"), "{cdata}");
    let cut = redact_secrets(
        "<Name>InternetGatewayDevice.ManagementServer.ConnectionRequestPassword</Name>\n<Value xsi:type=\"xsd:string\">cut-off-9",
    );
    assert!(!cut.contains("cut-off-9"), "{cut}");
    assert!(cut.ends_with("***"), "{cut}");
}

#[test]
fn test_audit_message_with_line_breaks_takes_one_entry() {
    let dir = temp_dir("audit_lines");
    let log_path = dir.join("tr069-fake.log");
    let logger = AuditLogger::with_limits(&log_path, 5, 4096);
    logger.record("INFO", "cwmp", "first");
    logger.record(
        "DEBUG",
        "cwmp_tx",
        "<SOAP-ENV:Body>\n<cwmp:RebootResponse>\r\n</cwmp:RebootResponse>\n</SOAP-ENV:Body>\n",
    );
    let snap = logger.snapshot();
    assert_eq!(snap.len(), 2);
    assert!(
        snap[1].ends_with(
            "[DEBUG] [cwmp_tx] <SOAP-ENV:Body> <cwmp:RebootResponse> </cwmp:RebootResponse> </SOAP-ENV:Body>"
        ),
        "{}",
        snap[1]
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_connection_request_rejects_wildcard_and_verifies_digest() {
    let audit = AuditLogger::new("/tmp/tr069-fake-cr-test.log");
    let creds = Arc::new(Mutex::new(ConnReqCreds {
        path: "/tr069".to_owned(),
        username: "cruser".to_owned(),
        password: "crpass".to_owned(),
    }));
    let trig = Arc::new(AtomicBool::new(false));

    // Must refuse 0.0.0.0
    let wildcard = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)];
    assert!(ConnectionRequestServer::start(&wildcard, Arc::clone(&creds), Arc::clone(&trig), audit.clone()).is_err());

    // Bind to explicit IP
    let explicit = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)];
    let srv = ConnectionRequestServer::start(&explicit, Arc::clone(&creds), Arc::clone(&trig), audit).unwrap();
    let port = srv.bound_addrs[0].port();

    // First GET -> 401 Digest challenge
    let mut s1 = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s1.write_all(b"GET /tr069 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut r1 = String::new();
    s1.read_to_string(&mut r1).unwrap();
    assert!(r1.starts_with("HTTP/1.1 401 Authorization Required\r\n"), "{r1}");
    assert!(r1.contains("\r\nServer: TR069 client TCP connection request Server\r\n"), "{r1}");
    assert!(!trig.load(Ordering::SeqCst));

    let www_auth = r1
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("www-authenticate:"))
        .unwrap()
        .split_once(':')
        .unwrap()
        .1
        .trim();
    let chal = parse_digest_challenge(www_auth).unwrap();
    // The challenge of the stock server: no qop, the path as domain.
    assert_eq!(
        www_auth,
        format!(
            "Digest realm=\"TR069 Client\", nonce=\"{}\", algorithm=\"MD5\", domain=\"/tr069\"",
            chal.nonce
        )
    );
    let auth_hdr = build_digest_authorization("cruser", "crpass", "GET", "/tr069", &chal, 1, "abcdef01");

    // Authenticated GET -> 200 OK & sets trigger
    let mut s2 = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let req2 = format!("GET /tr069 HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {auth_hdr}\r\nConnection: close\r\n\r\n");
    s2.write_all(req2.as_bytes()).unwrap();
    let mut r2 = String::new();
    s2.read_to_string(&mut r2).unwrap();
    assert_eq!(
        r2,
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nServer: TR069 client TCP connection request Server\r\nConnection: close\r\n\r\n"
    );
    assert!(trig.load(Ordering::SeqCst));
    srv.stop();
    let _ = fs::remove_file("/tmp/tr069-fake-cr-test.log");
}

/// The Digest challenge of a 401 response.
fn digest_challenge_of(response: &str) -> airoha_tr069_fake::http::DigestChallenge {
    let value = response
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("www-authenticate:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
        .expect("no WWW-Authenticate header");
    parse_digest_challenge(value).expect("unparsable Digest challenge")
}

/// Reads one response without a body, up to its blank line.
fn read_http_response_head(stream: &mut std::net::TcpStream) -> String {
    let mut raw = Vec::new();
    let mut b = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        match stream.read(&mut b) {
            Ok(1) => raw.push(b[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&raw).into_owned()
}

#[test]
fn test_connection_request_answers_the_retry_on_the_same_connection() {
    let dir = temp_dir("cr_same_conn");
    let audit = AuditLogger::new(dir.join("audit.log"));
    let creds = Arc::new(Mutex::new(ConnReqCreds {
        path: "/tr069".to_owned(),
        username: "cruser".to_owned(),
        password: "crpass".to_owned(),
    }));
    let trig = Arc::new(AtomicBool::new(false));
    let srv = ConnectionRequestServer::start(
        &["127.0.0.1:0".parse().unwrap()],
        creds,
        Arc::clone(&trig),
        audit,
    )
    .unwrap();

    // The stock server keeps the connection after its challenge and closes it after
    // the 200.
    let mut s = std::net::TcpStream::connect(srv.bound_addrs[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"GET /tr069 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    let challenge = read_http_response_head(&mut s);
    assert!(challenge.starts_with("HTTP/1.1 401 Authorization Required\r\n"), "{challenge}");
    assert!(!challenge.to_ascii_lowercase().contains("\r\nconnection:"), "{challenge}");
    assert!(!trig.load(Ordering::SeqCst));

    let auth_hdr = build_digest_authorization(
        "cruser",
        "crpass",
        "GET",
        "/tr069",
        &digest_challenge_of(&challenge),
        1,
        "abcdef01",
    );
    s.write_all(format!("GET /tr069 HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {auth_hdr}\r\n\r\n").as_bytes()).unwrap();
    let mut rest = String::new();
    s.read_to_string(&mut rest).unwrap();
    assert!(rest.starts_with("HTTP/1.1 200 OK\r\n"), "{rest}");
    assert!(rest.contains("\r\nConnection: close\r\n"), "{rest}");
    assert!(trig.load(Ordering::SeqCst));
    srv.stop();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_replies_have_the_stock_envelope_layout() {
    let dir = temp_dir("stock_layout");
    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    let mut reply = |cwmp_id: &str, rpc_xml: &str| {
        let request = format!(
            r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>{cwmp_id}</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body>{rpc_xml}</SOAP-ENV:Body></SOAP-ENV:Envelope>"#
        );
        let env = parse_cwmp_envelope(&request).unwrap();
        dispatch_rpc(&env, &mut model, &cfg).0.unwrap()
    };
    let head = |cwmp_id: &str| {
        format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:cwmp=\"urn:dslforum-org:cwmp-1-0\">\n<SOAP-ENV:Header>\n<cwmp:ID SOAP-ENV:mustUnderstand=\"1\">{cwmp_id}</cwmp:ID>\n</SOAP-ENV:Header>\n<SOAP-ENV:Body>\n"
        )
    };
    const TAIL: &str = "</SOAP-ENV:Body>\n</SOAP-ENV:Envelope>\n";

    // No XML declaration, one tag per line, a reply without content as two tags.
    assert_eq!(
        reply("r1", "<cwmp:Reboot><CommandKey>k1</CommandKey></cwmp:Reboot>"),
        format!("{}<cwmp:RebootResponse>\n</cwmp:RebootResponse>\n{TAIL}", head("r1"))
    );
    assert_eq!(
        reply("f1", "<cwmp:Upload/>"),
        format!(
            "{}<SOAP-ENV:Fault>\n<faultcode>Client</faultcode>\n<faultstring>CWMP fault</faultstring>\n<detail>\n<cwmp:Fault>\n<FaultCode>9000</FaultCode>\n<FaultString>Method not supported</FaultString>\n</cwmp:Fault>\n</detail>\n</SOAP-ENV:Fault>\n{TAIL}",
            head("f1")
        )
    );

    // Arrays carry xsi:type ahead of the arrayType.
    let methods = reply("m1", "<cwmp:GetRPCMethods/>");
    assert!(methods.contains("<cwmp:GetRPCMethodsResponse>\n<MethodList xsi:type=\"SOAP-ENC:Array\" SOAP-ENC:arrayType=\"cwmp:string["), "{methods}");
    let attrs = reply("a1", "<cwmp:GetParameterAttributes><ParameterNames><string>InternetGatewayDevice.DeviceInfo.SoftwareVersion</string></ParameterNames></cwmp:GetParameterAttributes>");
    assert!(attrs.contains("<ParameterList xsi:type=\"SOAP-ENC:Array\" SOAP-ENC:arrayType=\"cwmp:ParameterAttributeStruct[1]\">\n<ParameterAttributeStruct>\n<Name>InternetGatewayDevice.DeviceInfo.SoftwareVersion</Name>\n<Notification>"), "{attrs}");
    assert!(attrs.contains("</Notification>\n<AccessList xsi:type=\"SOAP-ENC:Array\" SOAP-ENC:arrayType=\"cwmp:String["), "{attrs}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_connection_request_failed_bind_releases_bound_listeners() {
    let audit = AuditLogger::new("/tmp/tr069-fake-cr-bind-test.log");
    let creds = Arc::new(Mutex::new(ConnReqCreds {
        path: "/tr069".to_owned(),
        username: "cruser".to_owned(),
        password: "crpass".to_owned(),
    }));
    let trig = Arc::new(AtomicBool::new(false));
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    // 192.0.2.1 (TEST-NET-1) is not assigned locally, so bind() fails with EADDRNOTAVAIL.
    let foreign = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port);

    assert!(ConnectionRequestServer::start(
        &[local, foreign],
        Arc::clone(&creds),
        Arc::clone(&trig),
        audit.clone()
    )
    .is_err());
    let srv = ConnectionRequestServer::start(&[local], creds, trig, audit)
        .expect("a failed start must release the listeners it already bound");
    assert_eq!(srv.bound_addrs, vec![local]);
    srv.stop();
    let _ = fs::remove_file("/tmp/tr069-fake-cr-bind-test.log");
}

#[test]
fn test_end_to_end_cwmp_session_with_mock_acs_digest_and_cookies() {
    let dir = temp_dir("e2e");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_handle = std::thread::spawn(move || {
        let mut step = 0;
        let mut authed_seen = false;
        for stream in listener.incoming().take(1) {
            let mut stream = stream.unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            loop {
                let Some((req_hdrs, req_body)) = read_http_request(&mut stream) else {
                    break;
                };
                if !req_hdrs.to_ascii_lowercase().contains("authorization: digest") {
                    let resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"ACS\", qop=\"auth\", nonce=\"n12345\", algorithm=MD5\r\nContent-Length: 0\r\n\r\n";
                    stream.write_all(resp.as_bytes()).unwrap();
                    continue;
                }
                authed_seen = true;
                if step == 0 {
                    assert!(req_body.contains("<cwmp:Inform>"));
                    let body = r#"<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>1</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
                    // Request headers and envelope layout of the stock client.
                    assert!(req_hdrs.contains(&format!("\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: TR069 Client 1.0\r\nContent-Type: text/xml; charset=utf-8\r\nAuthorization: Digest ")), "{req_hdrs}");
                    assert!(req_hdrs.ends_with(&format!("\r\nSOAPAction: Inform\r\nContent-Length: {}\r\n\r\n", req_body.len())), "{req_hdrs}");
                    assert!(!req_hdrs.to_ascii_lowercase().contains("\r\nconnection:"), "{req_hdrs}");
                    assert!(req_body.starts_with("<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding\" xmlns:xsd="), "{req_body}");
                    assert!(req_body.contains("<Event xsi:type=\"SOAP-ENC:Array\" SOAP-ENC:arrayType=\"cwmp:EventStruct[1]\">\n<EventStruct>\n<EventCode>0 BOOTSTRAP</EventCode>\n<CommandKey></CommandKey>\n</EventStruct>\n</Event>\n<MaxEnvelopes>1</MaxEnvelopes>\n"), "{req_body}");
                    assert!(req_body.ends_with("</ParameterList>\n</cwmp:Inform>\n</SOAP-ENV:Body>\n</SOAP-ENV:Envelope>\n"), "{req_body}");
                    // One random decimal cwmp:ID of at most 31 bits per session.
                    let session_id = req_body
                        .split_once("<cwmp:ID SOAP-ENV:mustUnderstand=\"1\">")
                        .and_then(|(_, rest)| rest.split_once("</cwmp:ID>"))
                        .map(|(id, _)| id.to_owned())
                        .unwrap();
                    assert!(session_id.parse::<u32>().is_ok_and(|n| n <= i32::MAX as u32), "{session_id}");
                    let resp = format!("HTTP/1.1 200 OK\r\nSet-Cookie: JSESSIONID=cwmp-cookie-1; Path=/\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                    stream.write_all(resp.as_bytes()).unwrap();
                    step = 1;
                } else if step == 1 {
                    assert!(req_hdrs.contains("Cookie: JSESSIONID=cwmp-cookie-1"));
                    assert!(req_body.is_empty());
                    assert!(req_hdrs.ends_with("\r\nContent-Type: text/xml\r\nContent-Length: 0\r\n\r\n"), "{req_hdrs}");
                    assert!(!req_hdrs.contains("SOAPAction"), "{req_hdrs}");
                    let body = r#"<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>99</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:SetParameterValues><ParameterList><ParameterValueStruct><Name>InternetGatewayDevice.ManagementServer.PeriodicInformInterval</Name><Value>300</Value></ParameterValueStruct></ParameterList><ParameterKey>acs-k1</ParameterKey></cwmp:SetParameterValues></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                    stream.write_all(resp.as_bytes()).unwrap();
                    step = 2;
                } else if step == 2 {
                    assert!(req_hdrs.contains("\r\nSOAPAction: \r\n"), "{req_hdrs}");
                    assert!(req_body.contains("<cwmp:ID SOAP-ENV:mustUnderstand=\"1\">99</cwmp:ID>\n</SOAP-ENV:Header>\n<SOAP-ENV:Body>\n<cwmp:SetParameterValuesResponse>\n<Status>0</Status>\n</cwmp:SetParameterValuesResponse>\n</SOAP-ENV:Body>\n</SOAP-ENV:Envelope>\n"), "{req_body}");
                    stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").unwrap();
                    break;
                }
            }
        }
        assert!(authed_seen);
    });

    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.audit_log_path = dir.join("audit.log").to_string_lossy().into_owned();
    cfg.tr069_ifname = String::new();
    cfg.acs_url = format!("http://127.0.0.1:{port}/acs");
    cfg.acs_username = "acsuser".to_owned();
    cfg.acs_password = "acspassword".to_owned();

    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    let audit = AuditLogger::new(&cfg.audit_log_path);
    let rt = InterfaceRuntime::default();
    let summary = run_cwmp_session(&mut cfg, &mut model, &rt, &[], 0, &audit, None).unwrap();
    assert_eq!(summary.rpcs_handled, 1);
    assert_eq!(cfg.periodic_inform_interval, 300);
    assert_eq!(
        model.get_value("InternetGatewayDevice.ManagementServer.ParameterKey"),
        Some("acs-k1")
    );
    server_handle.join().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

fn read_http_request(stream: &mut std::net::TcpStream) -> Option<(String, String)> {
    let mut raw = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match stream.read(&mut b) {
            Ok(0) => return None,
            Ok(_) => {
                raw.push(b[0]);
                if raw.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return None,
        }
    }
    let hdr_str = String::from_utf8_lossy(&raw).to_string();
    let cl = hdr_str
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut body = vec![0u8; cl];
    if cl > 0 {
        stream.read_exact(&mut body).ok()?;
    }
    Some((hdr_str, String::from_utf8_lossy(&body).to_string()))
}

#[test]
fn test_dns_packet_and_hashes_and_ipv6_bind_addrs() {
    assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let q = build_dns_query(0x1234, "acs.example.invalid", 28).unwrap();
    assert_eq!(&q[0..2], &[0x12, 0x34]);

    // Simulated AAAA response
    let mut resp = q.clone();
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[7] = 1; // ANCOUNT=1
    resp.extend_from_slice(&[0xc0, 0x0c, 0x00, 28, 0x00, 0x01, 0, 0, 0, 60, 0, 16]);
    resp.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    let ips = parse_dns_response(&resp, 0x1234, 28).unwrap();
    assert_eq!(ips, vec![IpAddr::V6("2001:db8::1".parse().unwrap())]);

    let rt = InterfaceRuntime {
        ifname: "tr069-if".to_owned(),
        ipv4_addrs: vec![Ipv4Addr::new(10, 20, 30, 40)],
        ipv6_addrs: vec![
            "fe80::1".parse().unwrap(),
            "2001:db8::40".parse().unwrap(),
        ],
        ipv6_tentative: vec![],
        dns_servers: vec![],
    };
    let binds = rt.conn_req_bind_addrs(7547);
    assert_eq!(binds.len(), 2);
}

#[test]
fn test_cwmp_rpcs_names_attributes_factory_reset_and_effects() {
    let dir = temp_dir("rpcs");
    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.software_version = "NNRRWrt-1.0.0".to_owned();

    let mut model = VirtualModel::load_or_init(&cfg).unwrap();

    let rpc_methods_xml = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>m1</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:GetRPCMethods/></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    let env = parse_cwmp_envelope(rpc_methods_xml).unwrap();
    let (reply, _, _) = dispatch_rpc(&env, &mut model, &cfg);
    let reply = reply.unwrap();
    assert!(reply.contains("GetRPCMethodsResponse"));
    // The methods this CPE answers, in the order of the stock method table. Inform and
    // TransferComplete are calls the CPE makes.
    let method_list: String = [
        "GetRPCMethods",
        "Reboot",
        "FactoryReset",
        "GetParameterNames",
        "GetParameterValues",
        "GetParameterAttributes",
        "SetParameterAttributes",
        "SetParameterValues",
        "AddObject",
        "DeleteObject",
        "Download",
    ]
    .iter()
    .map(|name| format!("<string>{name}</string>\n"))
    .collect();
    assert!(
        reply.contains(&format!(
            "<MethodList xsi:type=\"SOAP-ENC:Array\" SOAP-ENC:arrayType=\"cwmp:string[11]\">\n{method_list}</MethodList>\n"
        )),
        "{reply}"
    );

    let gpn_next = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>m2</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:GetParameterNames><ParameterPath>InternetGatewayDevice.DeviceInfo.</ParameterPath><NextLevel>1</NextLevel></cwmp:GetParameterNames></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    let env = parse_cwmp_envelope(gpn_next).unwrap();
    let (reply, _, _) = dispatch_rpc(&env, &mut model, &cfg);
    let reply = reply.unwrap();
    assert!(reply.contains("GetParameterNamesResponse"));
    assert!(reply.contains("InternetGatewayDevice.DeviceInfo.SoftwareVersion"));

    let gpn_sub = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>m3</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:GetParameterNames><ParameterPath>InternetGatewayDevice.ManagementServer.</ParameterPath><NextLevel>0</NextLevel></cwmp:GetParameterNames></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    let env = parse_cwmp_envelope(gpn_sub).unwrap();
    let (reply, _, _) = dispatch_rpc(&env, &mut model, &cfg);
    let reply = reply.unwrap();
    assert!(reply.contains("InternetGatewayDevice.ManagementServer.PeriodicInformInterval"));

    let spa_xml = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>m4</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:SetParameterAttributes><ParameterList><SetParameterAttributesStruct><Name>InternetGatewayDevice.DeviceInfo.ProvisioningCode</Name><NotificationChange>1</NotificationChange><Notification>2</Notification><AccessListChange>1</AccessListChange><AccessList><string>ACS</string></AccessList></SetParameterAttributesStruct></ParameterList></cwmp:SetParameterAttributes></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    let env = parse_cwmp_envelope(spa_xml).unwrap();
    let (reply, _, _) = dispatch_rpc(&env, &mut model, &cfg);
    assert!(reply.unwrap().contains("SetParameterAttributesResponse"));

    let gpa_xml = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>m5</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:GetParameterAttributes><ParameterNames><string>InternetGatewayDevice.DeviceInfo.ProvisioningCode</string></ParameterNames></cwmp:GetParameterAttributes></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    let env = parse_cwmp_envelope(gpa_xml).unwrap();
    let (reply, _, _) = dispatch_rpc(&env, &mut model, &cfg);
    let reply = reply.unwrap();
    assert!(reply.contains("<Notification>2</Notification>"));
    assert!(reply.contains("<string>ACS</string>"));

    let spv_mgmt = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>m6</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:SetParameterValues><ParameterList><ParameterValueStruct><Name>InternetGatewayDevice.ManagementServer.URL</Name><Value>https://new-acs.example.invalid:7547/cwmp</Value></ParameterValueStruct><ParameterValueStruct><Name>InternetGatewayDevice.ManagementServer.PeriodicInformEnable</Name><Value>0</Value></ParameterValueStruct><ParameterValueStruct><Name>InternetGatewayDevice.DeviceInfo.ProvisioningCode</Name><Value>MODIFIED</Value></ParameterValueStruct></ParameterList><ParameterKey>k-mgmt</ParameterKey></cwmp:SetParameterValues></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    let env = parse_cwmp_envelope(spv_mgmt).unwrap();
    let (reply, eff, _) = dispatch_rpc(&env, &mut model, &cfg);
    assert!(reply.unwrap().contains("SetParameterValuesResponse"));
    apply_effects_to_config(&mut cfg, &eff, None);
    assert_eq!(cfg.acs_url, "https://new-acs.example.invalid:7547/cwmp");
    assert!(!cfg.periodic_inform_enable);
    assert_eq!(
        model.get_value("InternetGatewayDevice.DeviceInfo.ProvisioningCode"),
        Some("MODIFIED")
    );

    let fr_xml = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>m7</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:FactoryReset/></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    let env = parse_cwmp_envelope(fr_xml).unwrap();
    let (reply, _, v_reboot) = dispatch_rpc(&env, &mut model, &cfg);
    assert!(reply.unwrap().contains("FactoryResetResponse"));
    assert!(v_reboot);
    assert_eq!(
        model.get_value("InternetGatewayDevice.DeviceInfo.ProvisioningCode"),
        Some("")
    );
    let codes: Vec<&str> = model
        .pending
        .events
        .iter()
        .map(|e| e.event_code.as_str())
        .collect();
    assert_eq!(codes, vec!["0 BOOTSTRAP", "1 BOOT"]);
    let reloaded = VirtualModel::load_or_init(&cfg).unwrap();
    assert_eq!(reloaded.pending.events.len(), 2);

    let _ = fs::remove_dir_all(&dir);
}

fn inform_response_http() -> String {
    let body = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Body><cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
}

fn acs_envelope(cwmp_id: &str, rpc_xml: &str) -> String {
    format!(
        r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>{cwmp_id}</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body>{rpc_xml}</SOAP-ENV:Body></SOAP-ENV:Envelope>"#
    )
}

fn acs_request_http(cwmp_id: &str, rpc_xml: &str) -> String {
    let body = acs_envelope(cwmp_id, rpc_xml);
    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
}

#[test]
fn test_session_has_no_rpc_cap_and_faults_unsupported_methods() {
    let dir = temp_dir("nocap");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (_, inform) = read_http_request(&mut stream).unwrap();
        assert!(inform.contains("<cwmp:Inform>"));
        stream.write_all(inform_response_http().as_bytes()).unwrap();
        let (_, empty) = read_http_request(&mut stream).unwrap();
        assert!(empty.is_empty());
        for i in 0..40 {
            let id = format!("r{i}");
            stream
                .write_all(acs_request_http(&id, "<cwmp:GetRPCMethods/>").as_bytes())
                .unwrap();
            let (_, reply) = read_http_request(&mut stream).unwrap();
            assert!(reply.contains("GetRPCMethodsResponse"), "reply {i}: {reply}");
            assert!(reply.contains(&format!(">{id}</cwmp:ID>")), "reply {i}: {reply}");
        }
        let upload = "<cwmp:Upload><CommandKey>k</CommandKey><FileType>1 Vendor Configuration File</FileType><URL>http://192.0.2.1/up</URL></cwmp:Upload>";
        stream
            .write_all(acs_request_http("up-1", upload).as_bytes())
            .unwrap();
        let (_, fault) = read_http_request(&mut stream).unwrap();
        assert!(fault.contains("<FaultCode>9000</FaultCode>"), "{fault}");
        assert!(fault.contains(">up-1</cwmp:ID>"), "{fault}");
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .unwrap();
    });

    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.acs_url = format!("http://{addr}/acs");
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    let rt = InterfaceRuntime::default();
    let audit = AuditLogger::new(dir.join("audit.log"));

    let summary = run_cwmp_session(&mut cfg, &mut model, &rt, &[], 0, &audit, None).unwrap();
    assert_eq!(summary.rpcs_handled, 41);
    srv.join().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_session_ends_after_repeated_malformed_soap() {
    let dir = temp_dir("malformed");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = std::thread::spawn(move || {
        let garbage = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n<notxml";
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = read_http_request(&mut stream).unwrap();
        stream.write_all(inform_response_http().as_bytes()).unwrap();
        let (_, empty) = read_http_request(&mut stream).unwrap();
        assert!(empty.is_empty());
        for _ in 0..2 {
            stream.write_all(garbage.as_bytes()).unwrap();
            let (_, fault) = read_http_request(&mut stream).unwrap();
            assert!(fault.contains("<FaultCode>9003</FaultCode>"), "{fault}");
        }
        stream.write_all(garbage.as_bytes()).unwrap();
        assert!(read_http_request(&mut stream).is_none());
    });

    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.acs_url = format!("http://{addr}/acs");
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    let rt = InterfaceRuntime::default();
    let audit = AuditLogger::new(dir.join("audit.log"));

    let err = run_cwmp_session(&mut cfg, &mut model, &rt, &[], 0, &audit, None).unwrap_err();
    assert!(err.to_string().contains("malformed SOAP"), "unexpected err: {err}");
    srv.join().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_download_boots_and_reports_transfer_complete_in_the_next_session() {
    let dir = temp_dir("download");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = std::thread::spawn(move || {
        // Session 1: the ACS orders the download.
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = read_http_request(&mut stream).unwrap();
        stream.write_all(inform_response_http().as_bytes()).unwrap();
        let (_, empty) = read_http_request(&mut stream).unwrap();
        assert!(empty.is_empty());
        let download = "<cwmp:Download><CommandKey>dl-7</CommandKey><FileType>1 Firmware Upgrade Image</FileType><URL>http://acs.example.invalid/images/fw-v2.0.0.bin</URL></cwmp:Download>";
        stream
            .write_all(acs_request_http("d1", download).as_bytes())
            .unwrap();
        let (_, reply) = read_http_request(&mut stream).unwrap();
        assert!(reply.contains("<Status>1</Status>"), "{reply}");
        assert!(reply.contains("<StartTime>0001-01-01T00:00:00Z</StartTime>"), "{reply}");
        assert!(reply.contains("<CompleteTime>0001-01-01T00:00:00Z</CompleteTime>"), "{reply}");
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .unwrap();
        drop(stream);

        // Session 2: the boot Inform, then TransferComplete.
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (_, inform) = read_http_request(&mut stream).unwrap();
        for code in ["1 BOOT", "7 TRANSFER COMPLETE", "M Download"] {
            assert!(
                inform.contains(&format!("<EventCode>{code}</EventCode>")),
                "{code}: {inform}"
            );
        }
        assert!(inform.contains("<CommandKey>dl-7</CommandKey>"), "{inform}");
        assert!(inform.contains("NNRRWrt-2.0.0"), "{inform}");
        stream.write_all(inform_response_http().as_bytes()).unwrap();
        let (_, tc) = read_http_request(&mut stream).unwrap();
        assert!(tc.contains("<cwmp:TransferComplete>"), "{tc}");
        assert!(tc.contains("<CommandKey>dl-7</CommandKey>"), "{tc}");
        assert!(tc.contains("<FaultCode>0</FaultCode>"), "{tc}");
        stream
            .write_all(acs_request_http("1", "<cwmp:TransferCompleteResponse/>").as_bytes())
            .unwrap();
        let (_, empty) = read_http_request(&mut stream).unwrap();
        assert!(empty.is_empty());
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .unwrap();
    });

    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.acs_url = format!("http://{addr}/acs");
    cfg.download_mappings.push(DownloadMapping {
        pattern: "fw-v2.0.0.bin".to_owned(),
        file_type: "1 Firmware Upgrade Image".to_owned(),
        target_version: "NNRRWrt-2.0.0".to_owned(),
    });
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    let boot_epoch = model.pending.virtual_boot_epoch;
    let rt = InterfaceRuntime::default();
    let audit = AuditLogger::new(dir.join("audit.log"));

    let first =
        run_cwmp_session(&mut cfg, &mut model, &rt, &["2 PERIODIC"], 0, &audit, None).unwrap();
    assert!(first.virtual_reboot_requested);
    assert_eq!(model.pending.virtual_boot_epoch, boot_epoch + 1);
    assert_eq!(model.pending.transfers.len(), 1);
    assert_eq!(model.pending.events.len(), 3);

    let second = run_cwmp_session(&mut cfg, &mut model, &rt, &[], 0, &audit, None).unwrap();
    assert!(!second.virtual_reboot_requested);
    assert!(model.pending.events.is_empty());
    assert!(model.pending.transfers.is_empty());
    let reloaded = VirtualModel::load_or_init(&cfg).unwrap();
    assert!(reloaded.pending.events.is_empty());
    assert!(reloaded.pending.transfers.is_empty());
    srv.join().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_failed_inform_keeps_events_and_the_retry_reports_its_count() {
    let dir = temp_dir("retry");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = std::thread::spawn(move || {
        // Attempt 1: the ACS answers the Inform with a fault.
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (_, inform) = read_http_request(&mut stream).unwrap();
        assert!(inform.contains("<RetryCount>0</RetryCount>"), "{inform}");
        assert!(inform.contains("<EventCode>0 BOOTSTRAP</EventCode>"), "{inform}");
        let fault = "<SOAP-ENV:Fault><faultcode>Server</faultcode><faultstring>CWMP fault</faultstring><detail><cwmp:Fault><FaultCode>8005</FaultCode><FaultString>Retry request</FaultString></cwmp:Fault></detail></SOAP-ENV:Fault>";
        stream
            .write_all(acs_request_http("1", fault).as_bytes())
            .unwrap();
        drop(stream);

        // Attempt 2: the Inform passes, the session breaks afterwards.
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (_, inform) = read_http_request(&mut stream).unwrap();
        assert!(inform.contains("<RetryCount>1</RetryCount>"), "{inform}");
        assert!(inform.contains("<EventCode>0 BOOTSTRAP</EventCode>"), "{inform}");
        assert!(inform.contains("<EventCode>M Reboot</EventCode>"), "{inform}");
        assert!(inform.contains("<EventCode>1 BOOT</EventCode>"), "{inform}");
        stream.write_all(inform_response_http().as_bytes()).unwrap();
        let _ = read_http_request(&mut stream).unwrap();
        stream
            .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });

    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.acs_url = format!("http://{addr}/acs");
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    model.handle_reboot("rb-9").unwrap();
    let rt = InterfaceRuntime::default();
    let audit = AuditLogger::new(dir.join("audit.log"));

    let err = run_cwmp_session(&mut cfg, &mut model, &rt, &[], 0, &audit, None).unwrap_err();
    assert!(!err.inform_accepted);
    assert!(err.to_string().contains("8005 Retry request"), "unexpected err: {err}");
    // A new model queues "0 BOOTSTRAP"; the reboot adds "M Reboot" and "1 BOOT".
    assert_eq!(model.pending.events.len(), 3);

    let err = run_cwmp_session(&mut cfg, &mut model, &rt, &[], 1, &audit, None).unwrap_err();
    assert!(err.inform_accepted);
    assert!(err.to_string().contains("HTTP 500"), "unexpected err: {err}");
    assert!(model.pending.events.is_empty());
    srv.join().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_retry_wait_doubles_from_five_seconds_and_stops_at_the_tenth_step() {
    assert_eq!(retry_wait_secs(1, 0), 5);
    assert_eq!(retry_wait_secs(1, 4), 9);
    assert_eq!(retry_wait_secs(1, 5), 5);
    assert_eq!(retry_wait_secs(2, 0), 10);
    assert_eq!(retry_wait_secs(2, 19), 19);
    assert_eq!(retry_wait_secs(10, 0), 2560);
    assert_eq!(retry_wait_secs(10, 2559), 5119);
    assert_eq!(retry_wait_secs(11, 0), 2560);
    assert_eq!(retry_wait_secs(0, 0), 5);
    assert!((2560..5120).contains(&retry_wait_secs(u32::MAX, u64::MAX)));
}

#[test]
fn test_acs_fault_reports_the_cwmp_fault_code() {
    let with_detail = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>Server</faultcode><faultstring>CWMP fault</faultstring><detail><cwmp:Fault><FaultCode>8005</FaultCode><FaultString>Retry request</FaultString></cwmp:Fault></detail></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    assert_eq!(
        parse_cwmp_envelope(with_detail).unwrap().message,
        CwmpMessage::Fault {
            code: "8005".to_owned(),
            message: "Retry request".to_owned(),
        }
    );
    let bare = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>Server</faultcode><faultstring>busy</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
    assert_eq!(
        parse_cwmp_envelope(bare).unwrap().message,
        CwmpMessage::Fault {
            code: "Server".to_owned(),
            message: "busy".to_owned(),
        }
    );
}

#[test]
fn test_booleans_take_any_letter_case_and_declared_types_any_prefix() {
    let dir = temp_dir("booleans");
    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    let enable = "InternetGatewayDevice.ManagementServer.PeriodicInformEnable";
    let interval = "InternetGatewayDevice.ManagementServer.PeriodicInformInterval";
    let pair = |name: &str, value: &str, declared: Option<&str>| {
        vec![(name.to_owned(), value.to_owned(), declared.map(str::to_owned))]
    };

    for (text, stored) in [("False", false), ("TRUE", true), ("0", false), ("True", true)] {
        let effects = model
            .set_parameter_values(&pair(enable, text, Some("xsd:boolean")), "k-bool")
            .unwrap();
        assert_eq!(effects.periodic_inform_enable, Some(stored), "{text}");
        assert_eq!(
            model.get_value(enable),
            Some(if stored { "true" } else { "false" }),
            "{text}"
        );
    }
    let fault = model
        .set_parameter_values(&pair(enable, "yes", None), "k-bool")
        .unwrap_err();
    assert_eq!((fault.code, fault.param_faults[0].1), (9003, 9007));

    // A declared type is compared by its name after the prefix.
    for declared in ["xs:boolean", "boolean", "XSD:Boolean"] {
        model
            .set_parameter_values(&pair(enable, "true", Some(declared)), "k-type")
            .unwrap();
    }
    model
        .set_parameter_values(&pair(interval, "600", Some("xs:int")), "k-type")
        .unwrap();
    let fault = model
        .set_parameter_values(&pair(enable, "true", Some("xsd:string")), "k-type")
        .unwrap_err();
    assert_eq!((fault.code, fault.param_faults[0].1), (9003, 9006));

    let names = parse_cwmp_envelope(&acs_envelope(
        "b1",
        "<cwmp:GetParameterNames><ParameterPath>InternetGatewayDevice.</ParameterPath><NextLevel>True</NextLevel></cwmp:GetParameterNames>",
    ))
    .unwrap();
    assert_eq!(
        names.message,
        CwmpMessage::GetParameterNames {
            parameter_path: "InternetGatewayDevice.".to_owned(),
            next_level: true,
        }
    );
    let attributes = parse_cwmp_envelope(&acs_envelope(
        "b2",
        &format!(
            "<cwmp:SetParameterAttributes><ParameterList><SetParameterAttributesStruct><Name>{enable}</Name><NotificationChange>TRUE</NotificationChange><Notification>2</Notification><AccessListChange>False</AccessListChange><AccessList><string>Subscriber</string></AccessList></SetParameterAttributesStruct></ParameterList></cwmp:SetParameterAttributes>"
        ),
    ))
    .unwrap();
    assert_eq!(
        attributes.message,
        CwmpMessage::SetParameterAttributes {
            items: vec![(enable.to_owned(), Some(2), None)],
        }
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_uptime_counts_from_the_last_virtual_boot() {
    let dir = temp_dir("uptime");
    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    let name = "InternetGatewayDevice.DeviceInfo.UpTime";
    let reported = |model: &VirtualModel| -> u64 {
        model.get_parameter_values(&[name.to_owned()]).unwrap()[0]
            .1
            .parse()
            .unwrap()
    };
    let kernel_uptime = || -> u64 {
        fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|text| text.split('.').next().and_then(|secs| secs.parse().ok()))
            .unwrap_or(0)
    };

    // Without a virtual boot the CPE has been up as long as the kernel.
    let at_start = kernel_uptime();
    let shown = reported(&model);
    assert!(at_start <= shown && shown <= kernel_uptime(), "{shown}");

    // A Reboot restarts the count. The mark is stored with the pending state, the model
    // keeps its placeholder.
    model.handle_reboot("rb-uptime").unwrap();
    let mark = model.pending.virtual_boot_mark.clone().unwrap();
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    assert_eq!(model.pending.virtual_boot_mark, Some(mark.clone()));
    assert_eq!(model.get_value(name), Some("0"));
    let shown = reported(&model);
    assert!(shown <= kernel_uptime() - at_start, "{shown}");

    // A mark taken during another kernel boot does not count.
    model.pending.virtual_boot_mark = Some(VirtualBootMark {
        boot_id: "another-boot".to_owned(),
        uptime_secs: u64::MAX,
    });
    assert!(reported(&model) >= at_start);

    // A mark ahead of the clock gives 0.
    model.pending.virtual_boot_mark = Some(VirtualBootMark {
        boot_id: mark.boot_id,
        uptime_secs: u64::MAX,
    });
    assert_eq!(reported(&model), 0);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_session_follows_redirects_and_keeps_the_configured_acs_url() {
    let dir = temp_dir("redirect");
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.2:0").unwrap();
    let first_addr = first.local_addr().unwrap();
    let second_addr = second.local_addr().unwrap();

    let srv = std::thread::spawn(move || {
        // The configured ACS hands the session to another host.
        let (mut stream, _) = first.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (hdrs, inform) = read_http_request(&mut stream).unwrap();
        assert!(hdrs.starts_with("POST /acs HTTP/1.1\r\n"), "{hdrs}");
        let moved = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{second_addr}/acs2\r\nSet-Cookie: first=1\r\nContent-Length: 0\r\n\r\n"
        );
        stream.write_all(moved.as_bytes()).unwrap();
        drop(stream);

        // The same Inform arrives there, without the cookie of the first host.
        let (mut stream, _) = second.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (hdrs, body) = read_http_request(&mut stream).unwrap();
        assert!(hdrs.starts_with("POST /acs2 HTTP/1.1\r\n"), "{hdrs}");
        assert!(hdrs.contains(&format!("Host: {second_addr}\r\n")), "{hdrs}");
        assert!(!hdrs.contains("Cookie:"), "{hdrs}");
        assert_eq!(body, inform);
        stream
            .write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: acs3?node=2\r\nSet-Cookie: second=2\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        drop(stream);

        // A relative Location stays on the host, which keeps its cookie.
        let (mut stream, _) = second.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (hdrs, body) = read_http_request(&mut stream).unwrap();
        assert!(hdrs.starts_with("POST /acs3?node=2 HTTP/1.1\r\n"), "{hdrs}");
        assert!(hdrs.contains("Cookie: second=2"), "{hdrs}");
        assert_eq!(body, inform);
        stream.write_all(inform_response_http().as_bytes()).unwrap();
        let (hdrs, body) = read_http_request(&mut stream).unwrap();
        assert!(hdrs.starts_with("POST /acs3?node=2 HTTP/1.1\r\n"), "{hdrs}");
        assert!(body.is_empty(), "{body}");
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .unwrap();
    });

    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.acs_url = format!("http://{first_addr}/acs");
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    let rt = InterfaceRuntime::default();
    let audit = AuditLogger::new(dir.join("audit.log"));

    let summary = run_cwmp_session(&mut cfg, &mut model, &rt, &[], 0, &audit, None).unwrap();
    assert_eq!(summary.rpcs_handled, 0);
    srv.join().unwrap();

    // A redirect serves one session: the configured URL stays.
    assert_eq!(cfg.acs_url, format!("http://{first_addr}/acs"));
    assert_eq!(
        model.get_value("InternetGatewayDevice.ManagementServer.URL"),
        Some(cfg.acs_url.as_str())
    );
    let entries = audit.snapshot().join("\n");
    for path in ["acs2", "acs3"] {
        let line = format!("ACS redirected the session to http://{second_addr}/{path}");
        assert!(entries.contains(&line), "{entries}");
    }
    assert!(!entries.contains("node=2"), "{entries}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_session_ends_at_the_sixth_redirect() {
    let dir = temp_dir("redirect-loop");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = std::thread::spawn(move || {
        for request in 0..6 {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let (hdrs, _) = read_http_request(&mut stream).unwrap();
            let path = if request == 0 { "/acs" } else { "/loop" };
            assert!(hdrs.starts_with(&format!("POST {path} HTTP/1.1\r\n")), "{hdrs}");
            stream
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        }
    });

    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.acs_url = format!("http://{addr}/acs");
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    let rt = InterfaceRuntime::default();
    let audit = AuditLogger::new(dir.join("audit.log"));

    let err = run_cwmp_session(&mut cfg, &mut model, &rt, &[], 0, &audit, None).unwrap_err();
    assert!(!err.inform_accepted);
    assert!(err.to_string().contains("more than 5 times"), "unexpected err: {err}");
    // The Inform was not accepted, so the event of the new model stays queued.
    assert_eq!(model.pending.events.len(), 1);
    srv.join().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_acs_url_change_queues_bootstrap() {
    fn set_url(model: &mut VirtualModel, url: &str) {
        model
            .set_parameter_values(
                &[("InternetGatewayDevice.ManagementServer.URL".to_owned(), url.to_owned(), None)],
                "k1",
            )
            .unwrap();
    }

    let dir = temp_dir("url-change");
    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.acs_url = "http://acs1.example.invalid:9090/acs".to_owned();
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    model.apply_config_overlay(&cfg).unwrap();
    // A new state directory starts with "0 BOOTSTRAP": take it as delivered.
    model.consume_pending_events().unwrap();
    assert!(model.pending.events.is_empty());

    // The same URL, also in another letter case, is no change.
    set_url(&mut model, "http://acs1.example.invalid:9090/acs");
    set_url(&mut model, "http://ACS1.example.invalid:9090/acs");
    assert!(model.pending.events.is_empty());

    // Two changes before the next Inform make one event.
    set_url(&mut model, "http://acs2.example.invalid:9090/acs");
    set_url(&mut model, "http://acs3.example.invalid:9090/acs");
    let events: Vec<&str> = model
        .pending
        .events
        .iter()
        .map(|ev| ev.event_code.as_str())
        .collect();
    assert_eq!(events, ["0 BOOTSTRAP"]);
    let mut reloaded = VirtualModel::load_or_init(&cfg).unwrap();
    assert_eq!(reloaded.pending.events, model.pending.events);

    // The local settings: unchanged ones leave the URL of the ACS, a new URL replaces it.
    reloaded.consume_pending_events().unwrap();
    reloaded.apply_config_overlay(&cfg).unwrap();
    assert!(reloaded.pending.events.is_empty());
    cfg.acs_url = "http://acs-from-luci.example.invalid/acs".to_owned();
    reloaded.apply_config_overlay(&cfg).unwrap();
    assert_eq!(
        reloaded.get_value("InternetGatewayDevice.ManagementServer.URL"),
        Some("http://acs-from-luci.example.invalid/acs")
    );
    assert_eq!(reloaded.pending.events.len(), 1);
    assert_eq!(reloaded.pending.events[0].event_code, "0 BOOTSTRAP");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_runtime_endpoints_differ_by_the_values_the_interface_offers() {
    let mut cfg = FakeConfig::default();
    cfg.conn_req_enable = true;
    let mut rt = InterfaceRuntime::default();
    rt.ipv4_addrs = vec![Ipv4Addr::new(10, 46, 0, 23)];
    let reported = RuntimeEndpoints::of(&cfg, &rt);
    assert_eq!(reported.conn_req_url.as_deref(), Some("http://10.46.0.23:7547/tr069"));
    assert_eq!(reported.ipv4, Some(Ipv4Addr::new(10, 46, 0, 23)));
    assert!(!reported.differs_from(&reported));

    rt.ipv4_addrs = vec![Ipv4Addr::new(10, 46, 0, 24)];
    assert!(RuntimeEndpoints::of(&cfg, &rt).differs_from(&reported));

    // Without an address the data model keeps what was reported.
    rt.ipv4_addrs.clear();
    let without_addr = RuntimeEndpoints::of(&cfg, &rt);
    assert_eq!(without_addr, RuntimeEndpoints { conn_req_url: None, ipv4: None });
    assert!(!without_addr.differs_from(&reported));
    assert!(reported.differs_from(&without_addr));

    // A disabled listener reports an empty URL.
    cfg.conn_req_enable = false;
    let disabled = RuntimeEndpoints::of(&cfg, &rt);
    assert_eq!(disabled.conn_req_url.as_deref(), Some(""));
    assert!(disabled.differs_from(&reported));
}

#[test]
fn test_format_unix_timestamp_iso8601_utc() {
    assert_eq!(format_unix_timestamp(0), "1970-01-01T00:00:00Z");
    assert_eq!(format_unix_timestamp(1_700_000_000), "2023-11-14T22:13:20Z");
    assert_eq!(format_unix_timestamp(1_709_164_800), "2024-02-29T00:00:00Z");
}

#[test]
fn test_load_json_file_rejects_invalid_pon_line() {
    let dir = temp_dir("bad-pon-line");
    let path = dir.join("cfg.json");
    fs::write(&path, r#"{"pon_line":"../bad"}"#).unwrap();
    let err = FakeConfig::load_json_file(&path).unwrap_err();
    assert!(err.contains("invalid pon_line"), "unexpected err: {err}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_cwmp_session_errors_on_empty_500_and_reuses_basic_auth() {
    let dir = temp_dir("basic-500");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let auth_headers = Arc::new(Mutex::new(Vec::<String>::new()));
    let auth_clone = Arc::clone(&auth_headers);

    let srv = std::thread::spawn(move || {
        let expected_auth = "Basic YWNzOmJpZ3NlY3JldA==";
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let _ = read_http_request(&mut stream).unwrap();
        stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"acs\"\r\nContent-Length: 0\r\n\r\n").unwrap();
        let (req2, _) = read_http_request(&mut stream).unwrap();
        auth_clone.lock().unwrap().push(req2);
        let resp_xml = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Body><cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
        let resp2 = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{resp_xml}", resp_xml.len());
        stream.write_all(resp2.as_bytes()).unwrap();
        let (req3, _) = read_http_request(&mut stream).unwrap();
        auth_clone.lock().unwrap().push(req3);
        let rpc_xml = r#"<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><SOAP-ENV:Header><cwmp:ID>1</cwmp:ID></SOAP-ENV:Header><SOAP-ENV:Body><cwmp:GetRPCMethods/></SOAP-ENV:Body></SOAP-ENV:Envelope>"#;
        let resp3 = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{rpc_xml}", rpc_xml.len());
        stream.write_all(resp3.as_bytes()).unwrap();
        let (req4, _) = read_http_request(&mut stream).unwrap();
        assert!(req4.to_ascii_lowercase().contains(&expected_auth.to_ascii_lowercase()));
        stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n").unwrap();
    });

    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.acs_url = format!("http://{addr}/acs");
    cfg.acs_username = "acs".to_owned();
    cfg.acs_password = "bigsecret".to_owned();
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    let rt = InterfaceRuntime::default();
    let audit = AuditLogger::new(dir.join("audit.log"));

    let err = run_cwmp_session(&mut cfg, &mut model, &rt, &["1 BOOT"], 0, &audit, None).unwrap_err();
    assert!(err.to_string().contains("HTTP 500"), "unexpected err: {err}");
    srv.join().unwrap();
    let captured = auth_headers.lock().unwrap();
    assert_eq!(captured.len(), 2);
    assert!(captured[0].to_ascii_lowercase().contains("authorization: basic ywnzomjpz3nly3jlda=="));
    assert!(captured[1].to_ascii_lowercase().contains("authorization: basic ywnzomjpz3nly3jlda=="));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_xml_unescape_single_pass() {
    assert_eq!(
        airoha_tr069_fake::cwmp::xml_unescape("&amp;lt;tag&amp;gt; &amp;amp; &lt;ok&gt;"),
        "&lt;tag&gt; &amp; <ok>"
    );
}

#[test]
fn test_conn_req_digest_nonce_replay_protection() {
    use airoha_tr069_fake::http::{build_digest_authorization, parse_digest_challenge, ConnectionRequestServer, ConnReqCreds};
    use std::net::TcpStream;
    use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};

    let dir = temp_dir("nonce_replay");
    let audit = AuditLogger::new(dir.join("audit.log"));
    let creds = Arc::new(Mutex::new(ConnReqCreds {
        path: "/cr".to_owned(),
        username: "cpe".to_owned(),
        password: "secret".to_owned(),
    }));
    let trig = Arc::new(AtomicBool::new(false));
    let srv = ConnectionRequestServer::start(&["127.0.0.1:0".parse().unwrap()], creds, Arc::clone(&trig), audit).unwrap();
    let addr = srv.bound_addrs[0];

    // 1. Unauthenticated request returns 401 with server-issued nonce
    let mut s1 = TcpStream::connect(addr).unwrap();
    s1.write_all(b"GET /cr HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = String::new();
    s1.read_to_string(&mut buf).unwrap();
    assert!(buf.starts_with("HTTP/1.1 401"), "expected 401, got: {buf}");
    let chal_line = buf
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("www-authenticate:"))
        .unwrap()
        .split_once(':').unwrap().1.trim();
    let mut chal = parse_digest_challenge(chal_line).unwrap();
    // The challenge offers no qop. A response with qop=auth is still accepted and has
    // its nc tracked, which steps 3 to 5 rely on.
    assert!(chal.qop.is_none());
    chal.qop = Some("auth".to_owned());

    // 2. Forged unissued nonce is rejected
    let mut forged_chal = chal.clone();
    forged_chal.nonce = "deadbeefdeadbeef".to_owned();
    let forged_auth = build_digest_authorization("cpe", "secret", "GET", "/cr", &forged_chal, 1, "abc123");
    let mut s2 = TcpStream::connect(addr).unwrap();
    s2.write_all(format!("GET /cr HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {forged_auth}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    buf.clear();
    s2.read_to_string(&mut buf).unwrap();
    assert!(buf.starts_with("HTTP/1.1 401"), "forged nonce must be rejected: {buf}");

    // 3. Valid nc=1 succeeds
    let auth_nc1 = build_digest_authorization("cpe", "secret", "GET", "/cr", &chal, 1, "abc123");
    let mut s3 = TcpStream::connect(addr).unwrap();
    s3.write_all(format!("GET /cr HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {auth_nc1}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    buf.clear();
    s3.read_to_string(&mut buf).unwrap();
    assert!(buf.starts_with("HTTP/1.1 200"), "valid nc=1 should pass: {buf}");
    assert!(trig.swap(false, Ordering::SeqCst));

    // 4. Replaying exact nc=1 is rejected
    let mut s4 = TcpStream::connect(addr).unwrap();
    s4.write_all(format!("GET /cr HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {auth_nc1}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    buf.clear();
    s4.read_to_string(&mut buf).unwrap();
    assert!(buf.starts_with("HTTP/1.1 401"), "replayed nc=1 must be rejected: {buf}");
    assert!(!trig.load(Ordering::SeqCst));

    // 5. Advancing nc=2 with same issued nonce succeeds
    let auth_nc2 = build_digest_authorization("cpe", "secret", "GET", "/cr", &chal, 2, "def456");
    let mut s5 = TcpStream::connect(addr).unwrap();
    s5.write_all(format!("GET /cr HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {auth_nc2}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    buf.clear();
    s5.read_to_string(&mut buf).unwrap();
    assert!(buf.starts_with("HTTP/1.1 200"), "advancing nc=2 should pass: {buf}");

    // 6. A response without qop, which the challenge asks for, passes once per nonce
    let mut s6 = TcpStream::connect(addr).unwrap();
    s6.write_all(b"GET /cr HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
    buf.clear();
    s6.read_to_string(&mut buf).unwrap();
    let auth_plain = build_digest_authorization("cpe", "secret", "GET", "/cr", &digest_challenge_of(&buf), 1, "abc123");
    assert!(!auth_plain.contains("qop="), "{auth_plain}");
    for expected in ["HTTP/1.1 200", "HTTP/1.1 401"] {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(format!("GET /cr HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {auth_plain}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        buf.clear();
        s.read_to_string(&mut buf).unwrap();
        assert!(buf.starts_with(expected), "response without qop, expected {expected}: {buf}");
    }

    srv.stop();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_overlay_preserves_acs_writes_until_uci_changes() {
    let dir = temp_dir("overlay_sig");
    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    cfg.acs_url = "http://acs1.example.invalid:9090/acs".to_owned();
    cfg.periodic_inform_interval = 300;

    let mut model = VirtualModel::load_or_init(&cfg).unwrap();
    model.apply_config_overlay(&cfg).unwrap();

    // ACS updates URL and PeriodicInformInterval
    model.set_parameter_values(
        &[
            ("InternetGatewayDevice.ManagementServer.URL".to_owned(), "http://acs-from-cwmp.example.invalid/acs".to_owned(), None),
            ("InternetGatewayDevice.ManagementServer.PeriodicInformInterval".to_owned(), "120".to_owned(), None),
        ],
        "k1",
    ).unwrap();

    // Unchanged UCI overlay on reboot/hotplug must NOT clobber ACS writes
    let mut reloaded = VirtualModel::load_or_init(&cfg).unwrap();
    reloaded.apply_config_overlay(&cfg).unwrap();
    assert_eq!(reloaded.get_value("InternetGatewayDevice.ManagementServer.URL"), Some("http://acs-from-cwmp.example.invalid/acs"));
    assert_eq!(reloaded.get_value("InternetGatewayDevice.ManagementServer.PeriodicInformInterval"), Some("120"));
    let eff = reloaded.current_management_effects();
    assert_eq!(eff.acs_url.as_deref(), Some("http://acs-from-cwmp.example.invalid/acs"));
    assert_eq!(eff.periodic_inform_interval, Some(120));

    // Explicit LuCI edit (changed URL in cfg) overrides ACS write (last-write-wins), while untouched interval stays 120
    cfg.acs_url = "http://acs-from-luci.example.invalid/acs".to_owned();
    reloaded.apply_config_overlay(&cfg).unwrap();
    assert_eq!(reloaded.get_value("InternetGatewayDevice.ManagementServer.URL"), Some("http://acs-from-luci.example.invalid/acs"));
    assert_eq!(reloaded.get_value("InternetGatewayDevice.ManagementServer.PeriodicInformInterval"), Some("120"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_apply_overlay_from_config_file_not_shadowed_by_acs_effects_and_mode_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("overlay_file");
    let cfg_path = dir.join("runtime.json");
    let state_dir = dir.join("state");

    let write_cfg = |acs_url: &str, interval: u64| {
        let body = format!(
            r#"{{"acs_url":"{acs_url}","acs_password":"secret","periodic_inform_interval":{interval},"state_dir":"{}"}}"#,
            state_dir.display()
        );
        fs::write(&cfg_path, body).unwrap();
    };

    write_cfg("http://acs1.example.invalid:9090/acs", 300);
    let (_, mut model) = apply_overlay_from_config(&cfg_path).unwrap();
    for fname in ["template.json", "model.json", "pending_events.json", "overlay.sig.json"] {
        let mode = fs::metadata(state_dir.join(fname)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{fname} must be mode 0600");
    }

    // ACS overrides URL and PeriodicInformInterval in persisted model.json
    model
        .set_parameter_values(
            &[
                ("InternetGatewayDevice.ManagementServer.URL".to_owned(), "http://acs-cwmp.example.invalid/acs".to_owned(), None),
                ("InternetGatewayDevice.ManagementServer.PeriodicInformInterval".to_owned(), "120".to_owned(), None),
            ],
            "k2",
        )
        .unwrap();

    // LuCI updates runtime.json URL while leaving interval at 300
    write_cfg("http://acs-luci.example.invalid/acs", 300);
    apply_overlay_from_config(&cfg_path).unwrap();

    let (eff_cfg, eff_model) = load_effective_cfg_and_model(&cfg_path).unwrap();
    assert_eq!(eff_cfg.acs_url, "http://acs-luci.example.invalid/acs");
    assert_eq!(eff_cfg.periodic_inform_interval, 120);
    assert_eq!(
        eff_model.get_value("InternetGatewayDevice.ManagementServer.URL"),
        Some("http://acs-luci.example.invalid/acs")
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_dump_status_and_model_redact_secrets_without_writing_flash() {
    let dir = temp_dir("readonly_dumps");
    let state_dir = dir.join("uninitialized_flash_state");
    let cfg_path = dir.join("runtime.json");
    let omci_path = dir.join("airoha-pond-tr069.line0.json");

    fs::write(
        &cfg_path,
        format!(
            r#"{{"pon_line":"line0","acs_url":"http://acs.example.invalid/acs","acs_password":"top-secret-acs","conn_req_password":"","state_dir":"{}"}}"#,  
            state_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        &omci_path,
        r#"{"management_vlan":46,"tr069_servers":[{"acs_url":"https://omci.example.invalid/acs","acs_username":"cpe","acs_password":"omci-secret-pw"}]}"#,
    )
    .unwrap();

    let cfg = FakeConfig::load_json_file(&cfg_path).unwrap();
    let model_json = dump_sanitized_model_json(&cfg).unwrap();
    assert!(!state_dir.exists(), "dump_sanitized_model_json must never create state_dir");
    assert!(!model_json.contains("top-secret-acs"));
    let parsed_model: JsonValue = serde_json::from_str(&model_json).unwrap();
    assert_eq!(
        parsed_model
            .get("model")
            .and_then(|m| m.get("InternetGatewayDevice.ManagementServer.Password"))
            .and_then(|p| p.get("value"))
            .and_then(|v| v.as_str()),
        Some("***")
    );
    assert_eq!(
        parsed_model
            .get("model")
            .and_then(|m| m.get("InternetGatewayDevice.ManagementServer.ConnectionRequestPassword"))
            .and_then(|p| p.get("value"))
            .and_then(|v| v.as_str()),
        Some("")
    );
    // UpTime is computed when read, so both columns show the same number.
    let uptime_of = |column: &str| {
        parsed_model
            .get(column)
            .and_then(|m| m.get("InternetGatewayDevice.DeviceInfo.UpTime"))
            .and_then(|p| p.get("value"))
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse::<u64>().ok())
    };
    assert!(uptime_of("model").is_some());
    assert_eq!(uptime_of("model"), uptime_of("template"));

    let status_json = dump_sanitized_status_json(
        &cfg_path,
        Some("line0"),
        Some(r#"{"running":true,"software_version":"NNRRWrt-1.0.0"}"#),
        &dir,
    );
    assert!(!state_dir.exists(), "dump_sanitized_status_json must never create state_dir");
    assert!(!status_json.contains("omci-secret-pw"));
    let parsed_status: JsonValue = serde_json::from_str(&status_json).unwrap();
    assert_eq!(
        parsed_status
            .get("omci")
            .and_then(|o| o.get("tr069_servers"))
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .and_then(|s| s.get("acs_password"))
            .and_then(|v| v.as_str()),
        Some("***")
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_audit_logger_multiprocess_sync_and_external_clear() {
    let dir = temp_dir("audit_multiprocess");
    let log_path = dir.join("audit.log");
    let daemon_log = AuditLogger::new(&log_path);
    let cli_log = AuditLogger::new(&log_path);

    daemon_log.record("INFO", "lifecycle", "daemon line 1");
    cli_log.record("INFO", "model", "cli line 2");
    let snap = daemon_log.snapshot();
    assert_eq!(snap.len(), 2);
    assert!(snap[0].contains("daemon line 1"));
    assert!(snap[1].contains("cli line 2"));

    // External clear-log must not be resurrected by daemon's in-memory buffer
    cli_log.clear();
    assert!(daemon_log.snapshot().is_empty());
    daemon_log.record("INFO", "cwmp", "daemon line 3");
    let after_clear = daemon_log.snapshot();
    assert_eq!(after_clear.len(), 1);
    assert!(after_clear[0].contains("daemon line 3"));
    let mode = fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_runtime_endpoints_and_parameter_key_mirror() {
    let dir = temp_dir("runtime_endpoints");
    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();

    model
        .update_runtime_endpoints(
            Some("http://10.46.0.23:7547/tr069"),
            Some(Ipv4Addr::new(10, 46, 0, 23)),
        )
        .unwrap();
    assert_eq!(
        model.get_value("InternetGatewayDevice.ManagementServer.ConnectionRequestURL"),
        Some("http://10.46.0.23:7547/tr069")
    );
    assert_eq!(
        model.get_value("Device.ManagementServer.ConnectionRequestURL"),
        Some("http://10.46.0.23:7547/tr069")
    );
    assert_eq!(
        model.get_value("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress"),
        Some("10.46.0.23")
    );

    let inst = model
        .add_object("InternetGatewayDevice.WANDevice.", "pk-add-1")
        .unwrap();
    assert_eq!(model.get_value("Device.ManagementServer.ParameterKey"), Some("pk-add-1"));
    model
        .delete_object(&format!("InternetGatewayDevice.WANDevice.{inst}."), "pk-del-1")
        .unwrap();
    assert_eq!(model.get_value("Device.ManagementServer.ParameterKey"), Some("pk-del-1"));

    // A local write keeps the key of the last change by the ACS.
    model
        .set_single_from_ui("InternetGatewayDevice.DeviceInfo.ProvisioningCode", "LOCAL")
        .unwrap();
    assert_eq!(
        model.get_value("InternetGatewayDevice.DeviceInfo.ProvisioningCode"),
        Some("LOCAL")
    );
    assert_eq!(
        model.get_value("InternetGatewayDevice.ManagementServer.ParameterKey"),
        Some("pk-del-1")
    );
    assert_eq!(model.get_value("Device.ManagementServer.ParameterKey"), Some("pk-del-1"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_digest_sess_xml_numeric_entities_and_http_body_caps() {
    for alg in ["MD5-sess", "SHA-256-sess"] {
        let raw_chal = format!(
            "Digest realm=\"TR069\", nonce=\"n123\", qop=\"auth\", algorithm={alg}"
        );
        let chal = parse_digest_challenge(&raw_chal).unwrap();
        let hdr = build_digest_authorization("acs", "pw123", "GET", "/tr069", &chal, 1, "cn456");
        assert!(
            verify_digest_authorization(&hdr, "GET", "acs", "pw123", "TR069", None),
            "{alg} verification should succeed"
        );
        assert!(!verify_digest_authorization(&hdr, "GET", "acs", "wrong", "TR069", None));
    }
    assert!(!verify_digest_authorization(
        "Digest username=\"acs\", realm=\"TR069\", nonce=\"n\", uri=\"/tr069\", algorithm=PLAIN, response=\"00\"",
        "GET",
        "acs",
        "pw123",
        "TR069",
        None,
    ));

    assert_eq!(xml_unescape("&#60;tag&#x3e; &amp; &#38;lt; &#X41;"), "<tag> & &lt; A");

    let huge_cl = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        MAX_HTTP_BODY_BYTES + 1
    );
    let mut cursor = std::io::Cursor::new(huge_cl.into_bytes());
    assert!(read_http_response(&mut cursor).is_err());

    let huge_chunk = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
        MAX_HTTP_BODY_BYTES + 1
    );
    let mut chunk_cursor = std::io::Cursor::new(huge_chunk.into_bytes());
    assert!(read_http_response(&mut chunk_cursor).is_err());
}

#[test]
fn test_roxmltree_custom_soap_namespaces_comments_cdata_and_dtd_rejection() {
    let dir = temp_dir("roxmltree_ns");
    let mut cfg = FakeConfig::default();
    cfg.state_dir = dir.to_string_lossy().into_owned();
    let mut model = VirtualModel::load_or_init(&cfg).unwrap();

    let custom_ns_xml = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<!-- carrier ACS preamble comment -->",
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" ",
        "xmlns:ns1=\"urn:dslforum-org:cwmp-1-2\" ",
        "xmlns:schemaInstance=\"http://www.w3.org/2001/XMLSchema-instance\">",
        "<soapenv:Header><ns1:ID soapenv:mustUnderstand=\"1\">ns-77</ns1:ID></soapenv:Header>",
        "<soapenv:Body><ns1:SetParameterValues>",
        "<ParameterList>",
        "<ParameterValueStruct>",
        "<Name>InternetGatewayDevice.DeviceInfo.ProvisioningCode</Name>",
        "<Value schemaInstance:type=\"xsd:string\">PRE<!-- mid-comment --><![CDATA[<RAW&CODE>]]>POST</Value>",
        "</ParameterValueStruct>",
        "</ParameterList>",
        "<ParameterKey>pk-ns-77</ParameterKey>",
        "</ns1:SetParameterValues></soapenv:Body></soapenv:Envelope>"
    );
    let env = parse_cwmp_envelope(custom_ns_xml).unwrap();
    assert_eq!(env.cwmp_id.as_deref(), Some("ns-77"));
    let (reply, _, _) = dispatch_rpc(&env, &mut model, &cfg);
    assert!(reply.unwrap().contains("SetParameterValuesResponse"));
    assert_eq!(
        model.get_value("InternetGatewayDevice.DeviceInfo.ProvisioningCode"),
        Some("PRE<RAW&CODE>POST")
    );

    // Reject DTD / XXE payloads cleanly
    let xxe_xml = concat!(
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe \"secret\">]>",
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">",
        "<SOAP-ENV:Body><GetRPCMethods/></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    );
    assert!(parse_cwmp_envelope(xxe_xml).is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_hickory_dns_cname_chain_and_tc_udp_to_tcp_fallback() {
    use hickory_proto::op::{Message, MessageType, ResponseCode};
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{Name, RData, Record};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use std::net::UdpSocket;

    let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp_listener.local_addr().unwrap().port();
    let udp_sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)).unwrap();
    udp_sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    let udp_handle = std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        // Query 1: alias.acs.invalid -> CNAME real.acs.invalid
        let (n1, peer1) = udp_sock.recv_from(&mut buf).unwrap();
        let q1 = Message::from_bytes(&buf[..n1]).unwrap();
        let qname1 = q1.queries()[0].name().clone();
        assert_eq!(qname1.to_ascii(), "alias.acs.invalid.");
        let mut r1 = Message::new();
        r1.set_id(q1.id());
        r1.set_message_type(MessageType::Response);
        r1.set_response_code(ResponseCode::NoError);
        r1.add_query(q1.queries()[0].clone());
        r1.add_answer(Record::from_rdata(
            qname1,
            60,
            RData::CNAME(CNAME(Name::from_ascii("real.acs.invalid.").unwrap())),
        ));
        udp_sock.send_to(&r1.to_bytes().unwrap(), peer1).unwrap();

        // Query 2: real.acs.invalid -> UDP TC=1 truncated, forcing TCP retry
        let (n2, peer2) = udp_sock.recv_from(&mut buf).unwrap();
        let q2 = Message::from_bytes(&buf[..n2]).unwrap();
        assert_eq!(q2.queries()[0].name().to_ascii(), "real.acs.invalid.");
        let mut r2 = Message::new();
        r2.set_id(q2.id());
        r2.set_message_type(MessageType::Response);
        r2.set_truncated(true);
        r2.add_query(q2.queries()[0].clone());
        udp_sock.send_to(&r2.to_bytes().unwrap(), peer2).unwrap();
    });

    let tcp_handle = std::thread::spawn(move || {
        let (mut stream, _) = tcp_listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).unwrap();
        let qlen = u16::from_be_bytes(len_buf) as usize;
        let mut qbuf = vec![0u8; qlen];
        stream.read_exact(&mut qbuf).unwrap();
        let q = Message::from_bytes(&qbuf).unwrap();
        assert_eq!(q.queries()[0].name().to_ascii(), "real.acs.invalid.");

        let mut resp = Message::new();
        resp.set_id(q.id());
        resp.set_message_type(MessageType::Response);
        resp.set_response_code(ResponseCode::NoError);
        resp.add_query(q.queries()[0].clone());
        resp.add_answer(Record::from_rdata(
            Name::from_ascii("real.acs.invalid.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 88))),
        ));
        let bytes = resp.to_bytes().unwrap();
        let rlen = (bytes.len() as u16).to_be_bytes();
        stream.write_all(&rlen).unwrap();
        stream.write_all(&bytes).unwrap();
    });

    let rt = InterfaceRuntime::default();
    let addrs = query_dns_server_addr(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        "alias.acs.invalid",
        1,
        &rt,
        Duration::from_secs(3),
    )
    .unwrap();
    assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 88))]);
    udp_handle.join().unwrap();
    tcp_handle.join().unwrap();
}

#[test]
fn test_httparse_fragmented_conn_req_chunked_response_and_digest_auth_int() {
    use airoha_tr069_fake::http::{
        build_digest_authorization_with_body, verify_digest_authorization_with_body,
    };

    // 1. Chunked response with chunk extension + trailer
    let raw_chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n5;ext=val\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: ok\r\n\r\n";
    let mut cur = std::io::Cursor::new(&raw_chunked[..]);
    let parsed = read_http_response(&mut cur).unwrap();
    assert_eq!(parsed.status, 200);
    assert_eq!(parsed.body, b"hello world");
    assert_eq!(parsed.set_cookies.len(), 2);

    // 2. Digest auth-int with SHA-256
    let chal = parse_digest_challenge("digest realm=\"ACS\", qop=\"auth-int\", nonce=\"n99\", algorithm=SHA-256").unwrap();
    let payload = b"<cwmp:Inform/>";
    let auth = build_digest_authorization_with_body(
        "u1",
        "p1",
        "POST",
        "/acs",
        &chal,
        1,
        "cn99",
        Some(payload),
    );
    assert!(verify_digest_authorization_with_body(&auth, "POST", Some(payload), "u1", "p1", "ACS", None));
    assert!(!verify_digest_authorization_with_body(&auth, "POST", Some(b"tampered"), "u1", "p1", "ACS", None));

    // 3. Fragmented TCP ConnectionRequest
    let dir = temp_dir("frag_cr");
    let audit = AuditLogger::new(dir.join("audit.log"));
    let creds = Arc::new(Mutex::new(ConnReqCreds {
        path: "/tr069".to_owned(),
        username: String::new(),
        password: String::new(),
    }));
    let trig = Arc::new(AtomicBool::new(false));
    let srv = ConnectionRequestServer::start(&["127.0.0.1:0".parse().unwrap()], creds, Arc::clone(&trig), audit).unwrap();
    let addr = srv.bound_addrs[0];
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(b"GET /tr069 ").unwrap();
    std::thread::sleep(Duration::from_millis(20));
    s.write_all(b"HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(trig.load(Ordering::SeqCst));
    srv.stop();
    let _ = fs::remove_dir_all(&dir);
}
