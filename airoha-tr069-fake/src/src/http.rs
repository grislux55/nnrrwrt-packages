// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use digest_auth::{
    Algorithm, AuthContext, AuthorizationHeader, Charset, HttpMethod, Qop, WwwAuthenticateHeader,
};
use url::Url;

use crate::audit::AuditLogger;
use crate::crypto_tls::{base64_encode, random_hex_nonce, TlsClientStream};
use crate::net_iso::{connect_isolated_tcp, InterfaceRuntime};

pub const MAX_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_CONN_REQ_HEADER_BYTES: usize = 8 * 1024;
/// Requests answered on one connection request connection: the challenge, the
/// authenticated retry and one spare.
const MAX_CONN_REQ_REQUESTS: usize = 3;
/// Time one connection request connection may hold its listener, and the longest wait
/// for more bytes within that time.
const CONN_REQ_TIMEOUT: Duration = Duration::from_secs(10);
const CONN_REQ_IDLE_TIMEOUT: Duration = Duration::from_secs(3);
/// Header values of the stock client and of its connection request server.
const ACS_USER_AGENT: &str = "TR069 Client 1.0";
const CONN_REQ_REALM: &str = "TR069 Client";
const CONN_REQ_SERVER: &str = "TR069 client TCP connection request Server";
/// Redirects one session follows, as the stock client.
const MAX_SESSION_REDIRECTS: u32 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlParts {
    pub is_https: bool,
    pub host: String,
    pub port: u16,
    pub path_query: String,
}

impl UrlParts {
    fn scheme(&self) -> &'static str {
        if self.is_https {
            "https"
        } else {
            "http"
        }
    }

    /// The URL a Location header names, absolute or relative to this one.
    fn resolve(&self, location: &str) -> Option<UrlParts> {
        let base = format!(
            "{}://{}:{}{}",
            self.scheme(),
            self.host,
            self.port,
            self.path_query
        );
        let target = Url::parse(&base).ok()?.join(location).ok()?;
        parse_url(target.as_str()).ok()
    }

    /// The URL for a log line, without the query, which may hold a token.
    fn without_query(&self) -> String {
        let path = self.path_query.split('?').next().unwrap_or_default();
        format!("{}://{}:{}{}", self.scheme(), self.host, self.port, path)
    }
}

pub fn parse_url(url_str: &str) -> io::Result<UrlParts> {
    let parsed = Url::parse(url_str).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACS URL must be a valid http:// or https:// URL",
        )
    })?;
    let is_https = match parsed.scheme() {
        "https" => true,
        "http" => false,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ACS URL must start with http:// or https://",
            ))
        }
    };
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty URL host"))?
        .to_owned();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid URL port"))?;
    let mut path_query = if parsed.path().is_empty() {
        "/".to_owned()
    } else {
        parsed.path().to_owned()
    };
    if let Some(q) = parsed.query() {
        path_query.push('?');
        path_query.push_str(q);
    }
    Ok(UrlParts {
        is_https,
        host,
        port,
        path_query,
    })
}

enum TransportStream {
    Plain(TcpStream),
    Tls(TlsClientStream),
}

impl Read for TransportStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TransportStream::Plain(s) => s.read(buf),
            TransportStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for TransportStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TransportStream::Plain(s) => s.write(buf),
            TransportStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TransportStream::Plain(s) => s.flush(),
            TransportStream::Tls(s) => s.flush(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub set_cookies: Vec<String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub qop: Option<String>,
    pub opaque: Option<String>,
    pub algorithm: String,
}

pub struct AcsHttpClient {
    url: UrlParts,
    username: String,
    password: String,
    insecure_tls: bool,
    rt: InterfaceRuntime,
    cookies: BTreeMap<String, String>,
    digest: Option<DigestChallenge>,
    use_basic: bool,
    nonce_count: u32,
    stream: Option<TransportStream>,
    /// Redirects followed in this session.
    redirects: u32,
    audit: AuditLogger,
}

impl AcsHttpClient {
    pub fn new(
        url_str: &str,
        username: &str,
        password: &str,
        insecure_tls: bool,
        rt: InterfaceRuntime,
        audit: AuditLogger,
    ) -> io::Result<Self> {
        let url = parse_url(url_str)?;
        Ok(Self {
            url,
            username: username.to_owned(),
            password: password.to_owned(),
            insecure_tls,
            rt,
            cookies: BTreeMap::new(),
            digest: None,
            use_basic: false,
            nonce_count: 0,
            stream: None,
            redirects: 0,
            audit,
        })
    }

    pub fn post_cwmp(&mut self, body: &str, soap_action: Option<&str>) -> io::Result<HttpResponse> {
        let body_bytes = body.as_bytes();
        // Challenges answered at the current URL.
        let mut challenges = 0;
        loop {
            let path_query = self.url.path_query.clone();
            let auth_header = self.build_auth_header("POST", &path_query, body_bytes);
            let resp = self.send_once(body_bytes, soap_action, auth_header.as_deref())?;
            if matches!(resp.status, 301 | 302 | 307) {
                // The same message goes to the new URL.
                self.follow_redirect(&resp)?;
                challenges = 0;
                continue;
            }
            if resp.status == 401 && challenges < 2 && !self.username.is_empty() {
                if let Some(chal) = resp.headers.get("www-authenticate") {
                    if chal.trim_start().to_ascii_lowercase().starts_with("digest ") {
                        if let Some(parsed) = parse_digest_challenge(chal) {
                            self.use_basic = false;
                            self.digest = Some(parsed);
                            self.nonce_count = 0;
                            challenges += 1;
                            continue;
                        }
                    } else if chal.trim_start().to_ascii_lowercase().starts_with("basic") {
                        self.digest = None;
                        self.use_basic = true;
                        challenges += 1;
                        continue;
                    }
                }
            }
            return Ok(resp);
        }
    }

    /// Moves the rest of the session to the Location of a 301, 302 or 307 answer. The
    /// stock client follows five redirects per session and authenticates anew at each
    /// target. The configured ACS URL stays as it is. Rules of this client: an https
    /// session stays on https, and cookies stay with the host that set them.
    fn follow_redirect(&mut self, resp: &HttpResponse) -> io::Result<()> {
        if self.redirects >= MAX_SESSION_REDIRECTS {
            return Err(io::Error::other(format!(
                "ACS redirected the session more than {MAX_SESSION_REDIRECTS} times"
            )));
        }
        let location = resp
            .headers
            .get("location")
            .filter(|location| !location.is_empty())
            .ok_or_else(|| {
                io::Error::other(format!("ACS sent HTTP {} without a Location", resp.status))
            })?;
        let target = self.url.resolve(location).ok_or_else(|| {
            io::Error::other(format!(
                "ACS sent HTTP {} with an unusable Location",
                resp.status
            ))
        })?;
        if self.url.is_https && !target.is_https {
            return Err(io::Error::other("ACS redirected an https session to http"));
        }
        if !target.host.eq_ignore_ascii_case(&self.url.host) {
            self.cookies.clear();
        }
        self.audit.record(
            "INFO",
            "cwmp",
            &format!("ACS redirected the session to {}", target.without_query()),
        );
        self.redirects += 1;
        self.stream = None;
        self.digest = None;
        self.use_basic = false;
        self.nonce_count = 0;
        self.url = target;
        Ok(())
    }

    fn build_basic_header(&self) -> String {
        let raw = format!("{}:{}", self.username, self.password);
        format!("Basic {}", base64_encode(raw.as_bytes()))
    }

    fn build_auth_header(&mut self, method: &str, uri: &str, body: &[u8]) -> Option<String> {
        if self.username.is_empty() {
            return None;
        }
        if let Some(chal) = self.digest.clone() {
            self.nonce_count += 1;
            let cnonce = random_hex_nonce();
            return Some(build_digest_authorization_with_body(
                &self.username,
                &self.password,
                method,
                uri,
                &chal,
                self.nonce_count,
                &cnonce,
                Some(body),
            ));
        }
        if self.use_basic {
            return Some(self.build_basic_header());
        }
        None
    }

    fn ensure_connected(&mut self) -> io::Result<&mut TransportStream> {
        if self.stream.is_none() {
            let tcp = connect_isolated_tcp(
                &self.url.host,
                self.url.port,
                &self.rt,
                Duration::from_secs(10),
            )?;
            let transport = if self.url.is_https {
                let sni = self.url.host.trim_matches(|c| c == '[' || c == ']');
                TransportStream::Tls(TlsClientStream::connect(tcp, sni, self.insecure_tls)?)
            } else {
                TransportStream::Plain(tcp)
            };
            self.stream = Some(transport);
        }
        Ok(self.stream.as_mut().unwrap())
    }

    fn send_once(
        &mut self,
        body: &[u8],
        soap_action: Option<&str>,
        auth_header: Option<&str>,
    ) -> io::Result<HttpResponse> {
        let req = self.format_request(body, soap_action, auth_header);
        let mut retry_reconnect = true;
        loop {
            let write_res = {
                let s = self.ensure_connected()?;
                s.write_all(&req).and_then(|_| s.flush())
            };
            if write_res.is_err() && retry_reconnect {
                self.stream = None;
                retry_reconnect = false;
                continue;
            }
            write_res?;
            let read_res = {
                let s = self.stream.as_mut().unwrap();
                read_http_response(s)
            };
            match read_res {
                Ok(resp) => {
                    for sc in &resp.set_cookies {
                        if let Some((k, v)) = sc.split(';').next().and_then(|kv| kv.split_once('=')) {
                            self.cookies.insert(k.trim().to_owned(), v.trim().to_owned());
                        }
                    }
                    if resp
                        .headers
                        .get("connection")
                        .map(|v| v.eq_ignore_ascii_case("close"))
                        .unwrap_or(false)
                    {
                        self.stream = None;
                    }
                    return Ok(resp);
                }
                Err(_) if retry_reconnect => {
                    self.stream = None;
                    retry_reconnect = false;
                    continue;
                }
                Err(e) => {
                    self.stream = None;
                    return Err(e);
                }
            }
        }
    }

    fn format_request(
        &self,
        body: &[u8],
        soap_action: Option<&str>,
        auth_header: Option<&str>,
    ) -> Vec<u8> {
        // Header order and text of the stock client. Host always carries the port,
        // SOAPAction is the bare method name of a CPE request and empty for a reply,
        // and an empty POST has neither SOAPAction nor a charset.
        let mut hdr = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: {ACS_USER_AGENT}\r\n",
            self.url.path_query, self.url.host, self.url.port
        );
        if !body.is_empty() {
            hdr.push_str("Content-Type: text/xml; charset=utf-8\r\n");
        }
        if let Some(auth) = auth_header {
            hdr.push_str(&format!("Authorization: {auth}\r\n"));
        }
        if !self.cookies.is_empty() {
            let cookie_str = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            hdr.push_str(&format!("Cookie: {cookie_str}\r\n"));
        }
        if body.is_empty() {
            hdr.push_str("Content-Type: text/xml\r\nContent-Length: 0\r\n\r\n");
        } else {
            hdr.push_str(&format!(
                "SOAPAction: {}\r\nContent-Length: {}\r\n\r\n",
                soap_action.unwrap_or_default(),
                body.len()
            ));
        }
        let mut bytes = hdr.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }
}

pub fn read_http_response<R: Read>(stream: &mut R) -> io::Result<HttpResponse> {
    let mut raw = Vec::with_capacity(512);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if raw.len() >= MAX_HTTP_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response headers exceed 64 KiB limit",
            ));
        }
        let max_read = chunk.len().min(MAX_HTTP_HEADER_BYTES - raw.len());
        let n = stream.read(&mut chunk[..max_read])?;
        if n == 0 {
            if raw.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "empty HTTP response",
                ));
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed HTTP headers",
            ));
        }
        raw.extend_from_slice(&chunk[..n]);
        let mut hdr_slots = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut hdr_slots);
        match resp.parse(&raw) {
            Ok(httparse::Status::Complete(offset)) => break offset,
            Ok(httparse::Status::Partial) => continue,
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid HTTP response headers: {err}"),
                ))
            }
        }
    };

    let (status, headers, set_cookies) = {
        let mut hdr_slots = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut hdr_slots);
        let _ = parsed.parse(&raw[..header_end]).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("HTTP parse error: {e}"))
        })?;
        let status = parsed
            .code
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status code"))?;
        let mut headers = BTreeMap::new();
        let mut set_cookies = Vec::new();
        for h in parsed.headers.iter() {
            let key_lower = h.name.trim().to_ascii_lowercase();
            let val = std::str::from_utf8(h.value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 HTTP header"))?
                .trim()
                .to_owned();
            if key_lower == "set-cookie" {
                set_cookies.push(val.clone());
            }
            headers.insert(key_lower, val);
        }
        (status, headers, set_cookies)
    };

    let leftover = &raw[header_end..];
    let mut body_stream = Cursor::new(leftover).chain(stream);

    let is_chunked = headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    let body = if is_chunked {
        read_chunked_body(&mut body_stream)?
    } else if let Some(cl_raw) = headers.get("content-length") {
        let cl = cl_raw.parse::<usize>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP Content-Length")
        })?;
        if cl > MAX_HTTP_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP Content-Length exceeds 2 MiB limit",
            ));
        }
        let mut buf = vec![0u8; cl];
        body_stream.read_exact(&mut buf)?;
        buf
    } else if status == 204 || (100..200).contains(&status) || status == 304 {
        Vec::new()
    } else {
        let mut buf = Vec::new();
        let _ = body_stream
            .take((MAX_HTTP_BODY_BYTES + 1) as u64)
            .read_to_end(&mut buf)?;
        if buf.len() > MAX_HTTP_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response body exceeds 2 MiB limit",
            ));
        }
        buf
    };
    Ok(HttpResponse {
        status,
        headers,
        set_cookies,
        body,
    })
}

fn read_chunked_body<R: Read>(stream: &mut R) -> io::Result<Vec<u8>> {
    let mut reader = BufReader::new(stream);
    let mut out = Vec::new();
    loop {
        let mut line = Vec::new();
        let n_hdr = (&mut reader).take(8192).read_until(b'\n', &mut line)?;
        if n_hdr == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated HTTP chunk header",
            ));
        }
        let size = match httparse::parse_chunk_size(&line) {
            Ok(httparse::Status::Complete((_, sz))) => usize::try_from(sz).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "HTTP chunk size overflow")
            })?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HTTP chunk size",
                ))
            }
        };
        if size == 0 {
            let mut trailer = String::new();
            loop {
                trailer.clear();
                let n = (&mut reader).take(8192).read_line(&mut trailer)?;
                if n == 0 || trailer == "\r\n" || trailer == "\n" {
                    break;
                }
            }
            break;
        }
        if size > MAX_HTTP_BODY_BYTES || out.len().saturating_add(size) > MAX_HTTP_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP chunked body exceeds 2 MiB limit",
            ));
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        out.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
        if &crlf != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing CRLF after HTTP chunk",
            ));
        }
    }
    Ok(out)
}

fn canonicalize_algorithm_name(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "MD5" => Some("MD5"),
        "MD5-SESS" => Some("MD5-sess"),
        "SHA-256" => Some("SHA-256"),
        "SHA-256-SESS" => Some("SHA-256-sess"),
        "SHA-512-256" => Some("SHA-512-256"),
        "SHA-512-256-SESS" => Some("SHA-512-256-sess"),
        _ => None,
    }
}

fn normalize_digest_header(header: &str) -> Option<String> {
    let trimmed = header.trim();
    if trimmed.len() < 7 || !trimmed[..6].eq_ignore_ascii_case("digest") {
        return None;
    }
    let rest = &trimmed[6..];
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let mut normalized = format!("Digest {}", rest.trim_start());
    for (bad, good) in [
        ("algorithm=md5-sess", "algorithm=MD5-sess"),
        ("algorithm=MD5-SESS", "algorithm=MD5-sess"),
        ("algorithm=md5", "algorithm=MD5"),
        ("algorithm=sha-256-sess", "algorithm=SHA-256-sess"),
        ("algorithm=SHA-256-SESS", "algorithm=SHA-256-sess"),
        ("algorithm=sha-256", "algorithm=SHA-256"),
        ("algorithm=sha-512-256-sess", "algorithm=SHA-512-256-sess"),
        ("algorithm=SHA-512-256-SESS", "algorithm=SHA-512-256-sess"),
        ("algorithm=sha-512-256", "algorithm=SHA-512-256"),
    ] {
        normalized = normalized.replace(bad, good);
    }
    Some(normalized)
}

pub fn parse_digest_challenge(header: &str) -> Option<DigestChallenge> {
    let norm = normalize_digest_header(header)?;
    let prompt = WwwAuthenticateHeader::parse(&norm).ok()?;
    let qop = prompt.qop.as_ref().and_then(|qops| {
        if qops.contains(&Qop::AUTH) {
            Some("auth".to_owned())
        } else {
            qops.first().map(ToString::to_string)
        }
    });
    Some(DigestChallenge {
        realm: prompt.realm,
        nonce: prompt.nonce,
        qop,
        opaque: prompt.opaque,
        algorithm: prompt.algorithm.to_string(),
    })
}

pub fn build_digest_authorization(
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    chal: &DigestChallenge,
    nc: u32,
    cnonce: &str,
) -> String {
    build_digest_authorization_with_body(
        username,
        password,
        method,
        uri,
        chal,
        nc,
        cnonce,
        Some(&[]),
    )
}

pub fn build_digest_authorization_with_body(
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    chal: &DigestChallenge,
    nc: u32,
    cnonce: &str,
    body: Option<&[u8]>,
) -> String {
    let algo = canonicalize_algorithm_name(&chal.algorithm)
        .and_then(|s| Algorithm::from_str(s).ok())
        .unwrap_or_default();
    let qop = chal
        .qop
        .as_deref()
        .and_then(|q| Qop::from_str(&q.trim().to_ascii_lowercase()).ok())
        .map(|q| vec![q]);
    let mut prompt = WwwAuthenticateHeader {
        domain: None,
        realm: chal.realm.clone(),
        nonce: chal.nonce.clone(),
        opaque: chal.opaque.clone(),
        stale: false,
        algorithm: algo,
        qop,
        userhash: false,
        charset: Charset::ASCII,
        nc: nc.saturating_sub(1),
    };
    let mut ctx = AuthContext::new_with_method(
        username,
        password,
        uri,
        body,
        HttpMethod::from(method),
    );
    if !cnonce.is_empty() {
        ctx.set_custom_cnonce(cnonce);
    }
    match prompt.respond(&ctx) {
        Ok(hdr) => hdr.to_header_string(),
        Err(_) => String::new(),
    }
}

#[derive(Clone, Debug)]
struct IssuedNonce {
    issued_at: std::time::Instant,
    last_nc: u32,
    consumed_without_qop: bool,
}

#[derive(Default)]
pub struct NonceTracker {
    entries: BTreeMap<String, IssuedNonce>,
}

impl NonceTracker {
    pub fn issue(&mut self) -> String {
        self.prune_expired();
        if self.entries.len() >= 128 {
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.issued_at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
        let nonce = random_hex_nonce();
        self.entries.insert(
            nonce.clone(),
            IssuedNonce {
                issued_at: std::time::Instant::now(),
                last_nc: 0,
                consumed_without_qop: false,
            },
        );
        nonce
    }

    fn prune_expired(&mut self) {
        let ttl = Duration::from_secs(120);
        self.entries.retain(|_, v| v.issued_at.elapsed() < ttl);
    }

    pub fn validate_and_advance(
        &mut self,
        nonce: &str,
        qop: Option<&str>,
        nc_hex: Option<&str>,
    ) -> bool {
        self.prune_expired();
        let Some(state) = self.entries.get_mut(nonce) else {
            return false;
        };
        if let Some(q) = qop {
            if !q.eq_ignore_ascii_case("auth") && !q.eq_ignore_ascii_case("auth-int") {
                return false;
            }
            let Some(nc_str) = nc_hex else {
                return false;
            };
            let Ok(nc_val) = u32::from_str_radix(nc_str, 16) else {
                return false;
            };
            if nc_val == 0 || nc_val <= state.last_nc {
                return false;
            }
            state.last_nc = nc_val;
            true
        } else {
            if state.consumed_without_qop {
                return false;
            }
            state.consumed_without_qop = true;
            true
        }
    }
}

fn header_contains_nc_param(norm_header: &str) -> bool {
    let lower = norm_header.to_ascii_lowercase();
    lower.contains(" nc=") || lower.contains(",nc=") || lower.contains("\tnc=")
}

pub fn verify_digest_authorization(
    auth_header: &str,
    method: &str,
    expected_user: &str,
    expected_pass: &str,
    expected_realm: &str,
    nonce_tracker: Option<&Mutex<NonceTracker>>,
) -> bool {
    verify_digest_authorization_with_body(
        auth_header,
        method,
        Some(&[]),
        expected_user,
        expected_pass,
        expected_realm,
        nonce_tracker,
    )
}

pub fn verify_digest_authorization_with_body(
    auth_header: &str,
    method: &str,
    body: Option<&[u8]>,
    expected_user: &str,
    expected_pass: &str,
    expected_realm: &str,
    nonce_tracker: Option<&Mutex<NonceTracker>>,
) -> bool {
    if expected_user.is_empty() {
        return true;
    }
    let Some(norm) = normalize_digest_header(auth_header) else {
        return false;
    };
    let Ok(parsed) = AuthorizationHeader::parse(&norm) else {
        return false;
    };
    if parsed.realm != expected_realm {
        return false;
    }
    let user_ok = if parsed.userhash {
        let expected_hash = parsed
            .algorithm
            .hash(format!("{expected_user}:{expected_realm}").as_bytes());
        expected_hash.eq_ignore_ascii_case(&parsed.username)
    } else {
        parsed.username == expected_user
    };
    if !user_ok {
        return false;
    }
    if parsed.qop.is_some() && !header_contains_nc_param(&norm) {
        return false;
    }
    let received_response = parsed.response.clone();
    let mut check = parsed.clone();
    let mut ctx = AuthContext::new_with_method(
        expected_user,
        expected_pass,
        parsed.uri.as_str(),
        body,
        HttpMethod::from(method),
    );
    if let Some(cn) = &parsed.cnonce {
        ctx.set_custom_cnonce(cn.as_str());
    }
    check.digest(&ctx);
    if !check.response.eq_ignore_ascii_case(&received_response) {
        return false;
    }
    if let Some(tracker) = nonce_tracker {
        let qop_str = parsed.qop.map(|q| q.to_string());
        let nc_hex = parsed.qop.map(|_| format!("{:08x}", parsed.nc));
        let mut guard = tracker.lock().expect("nonce tracker mutex poisoned");
        return guard.validate_and_advance(
            &parsed.nonce,
            qop_str.as_deref(),
            nc_hex.as_deref(),
        );
    }
    true
}

#[derive(Clone, Debug)]
pub struct ConnReqCreds {
    pub path: String,
    pub username: String,
    pub password: String,
}

pub struct ConnectionRequestServer {
    pub bound_addrs: Vec<SocketAddr>,
    stop: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl ConnectionRequestServer {
    pub fn start(
        bind_addrs: &[SocketAddr],
        creds: Arc<Mutex<ConnReqCreds>>,
        trigger_flag: Arc<AtomicBool>,
        audit: AuditLogger,
    ) -> io::Result<Self> {
        for addr in bind_addrs {
            if addr.ip().is_unspecified() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ConnectionRequest requires a concrete tr069 interface IP",
                ));
            }
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut bound_addrs = Vec::new();
        let mut handles = Vec::new();
        let realm = CONN_REQ_REALM.to_owned();
        let nonce_tracker = Arc::new(Mutex::new(NonceTracker::default()));
        let mut listeners = Vec::with_capacity(bind_addrs.len());
        for addr in bind_addrs {
            let listener = TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            bound_addrs.push(listener.local_addr()?);
            listeners.push(listener);
        }
        for listener in listeners {
            let stop_c = Arc::clone(&stop);
            let creds_c = Arc::clone(&creds);
            let trig_c = Arc::clone(&trigger_flag);
            let audit_c = audit.clone();
            let realm_c = realm.clone();
            let tracker_c = Arc::clone(&nonce_tracker);
            let handle = std::thread::spawn(move || {
                while !stop_c.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, peer)) => {
                            let deadline = Instant::now() + CONN_REQ_TIMEOUT;
                            for _ in 0..MAX_CONN_REQ_REQUESTS {
                                if !handle_conn_req(
                                    &mut stream,
                                    deadline,
                                    peer,
                                    &creds_c,
                                    &realm_c,
                                    &tracker_c,
                                    &trig_c,
                                    &audit_c,
                                ) {
                                    break;
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(_) => break,
                    }
                }
            });
            handles.push(handle);
        }
        Ok(Self {
            bound_addrs,
            stop,
            handles,
        })
    }

    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.handles {
            let _ = h.join();
        }
    }
}

struct ConnReqRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
    /// The peer asked for the connection to end after the response.
    close: bool,
}

/// Reads request bytes, waiting no longer than the idle timeout or the time left until
/// `deadline`. None on a timeout, an error or the end of the stream.
fn read_conn_req_bytes(
    stream: &mut TcpStream,
    deadline: Instant,
    buf: &mut [u8],
) -> Option<usize> {
    let left = deadline.checked_duration_since(Instant::now())?;
    if left.is_zero() {
        return None;
    }
    stream
        .set_read_timeout(Some(left.min(CONN_REQ_IDLE_TIMEOUT)))
        .ok()?;
    match stream.read(buf) {
        Ok(n) if n > 0 => Some(n),
        _ => None,
    }
}

fn read_conn_req_request(stream: &mut TcpStream, deadline: Instant) -> Option<ConnReqRequest> {
    let mut raw = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if raw.len() >= MAX_CONN_REQ_HEADER_BYTES {
            return None;
        }
        let max_read = chunk.len().min(MAX_CONN_REQ_HEADER_BYTES - raw.len());
        let n = read_conn_req_bytes(stream, deadline, &mut chunk[..max_read])?;
        raw.extend_from_slice(&chunk[..n]);
        let mut hdr_slots = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut hdr_slots);
        match req.parse(&raw) {
            Ok(httparse::Status::Complete(offset)) => break offset,
            Ok(httparse::Status::Partial) => continue,
            Err(_) => return None,
        }
    };

    let (method, req_path, auth_hdr, content_len, close) = {
        let mut hdr_slots = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut hdr_slots);
        req.parse(&raw[..header_end]).ok()?;
        let method = req.method.unwrap_or("GET").to_owned();
        let req_path = req.path.unwrap_or("/").to_owned();
        let mut auth_hdr = None;
        let mut content_len = 0usize;
        // HTTP/1.0 ends the connection unless the peer asks to keep it.
        let mut close = req.version == Some(0);
        for h in req.headers.iter() {
            if h.name.eq_ignore_ascii_case("authorization") {
                if let Ok(v) = std::str::from_utf8(h.value) {
                    auth_hdr = Some(v.trim().to_owned());
                }
            } else if h.name.eq_ignore_ascii_case("content-length") {
                if let Ok(v) = std::str::from_utf8(h.value) {
                    content_len = v.trim().parse::<usize>().ok().filter(|&n| n <= 65_536)?;
                }
            } else if h.name.eq_ignore_ascii_case("connection") {
                if let Ok(v) = std::str::from_utf8(h.value) {
                    for token in v.split(',').map(str::trim) {
                        if token.eq_ignore_ascii_case("close") {
                            close = true;
                        } else if token.eq_ignore_ascii_case("keep-alive") {
                            close = false;
                        }
                    }
                }
            }
        }
        (method, req_path, auth_hdr, content_len, close)
    };

    let mut body = raw[header_end..].to_vec();
    body.truncate(content_len);
    while body.len() < content_len {
        let max_read = chunk.len().min(content_len - body.len());
        let n = read_conn_req_bytes(stream, deadline, &mut chunk[..max_read])?;
        body.extend_from_slice(&chunk[..n]);
    }
    Some(ConnReqRequest {
        method,
        path: req_path,
        authorization: auth_hdr,
        body,
        close,
    })
}

/// Answers one connection request. Returns true when the peer may send another request
/// on the same connection, which the stock server allows after its challenge.
fn handle_conn_req(
    stream: &mut TcpStream,
    deadline: Instant,
    peer: SocketAddr,
    creds: &Arc<Mutex<ConnReqCreds>>,
    realm: &str,
    nonce_tracker: &Arc<Mutex<NonceTracker>>,
    trigger_flag: &Arc<AtomicBool>,
    audit: &AuditLogger,
) -> bool {
    let Some(ConnReqRequest {
        method,
        path: req_path,
        authorization: auth_hdr,
        body,
        close,
    }) = read_conn_req_request(stream, deadline)
    else {
        return false;
    };
    let cfg = creds.lock().expect("creds mutex poisoned").clone();
    let path_match = req_path.split('?').next().unwrap_or(&req_path) == cfg.path;
    if !path_match {
        let _ = stream.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return false;
    }
    let authorized = if cfg.username.is_empty() {
        true
    } else if let Some(auth) = auth_hdr.as_deref() {
        verify_digest_authorization_with_body(
            auth,
            &method,
            Some(&body),
            &cfg.username,
            &cfg.password,
            realm,
            Some(nonce_tracker),
        )
    } else {
        false
    };
    if !authorized {
        let nonce = nonce_tracker
            .lock()
            .expect("nonce tracker mutex poisoned")
            .issue();
        // Challenge of the stock server: no qop, and no Connection header, because the
        // peer may answer on the same connection.
        let domain = digest_domain(&cfg.path);
        let resp = format!(
            "HTTP/1.1 401 Authorization Required\r\nContent-Length: 0\r\nServer: {CONN_REQ_SERVER}\r\nWWW-Authenticate: Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=\"MD5\", domain=\"{domain}\"\r\n\r\n"
        );
        // A request without credentials is the first half of every exchange.
        if auth_hdr.is_some() {
            audit.record(
                "WARN",
                "conn_req",
                &format!("Unauthorized ConnectionRequest from {peer} path={req_path}"),
            );
        }
        return stream.write_all(resp.as_bytes()).is_ok() && !close;
    }
    trigger_flag.store(true, Ordering::SeqCst);
    audit.record(
        "INFO",
        "conn_req",
        &format!("Accepted ConnectionRequest from {peer} path={req_path}"),
    );
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nServer: {CONN_REQ_SERVER}\r\nConnection: close\r\n\r\n"
    );
    let _ = stream.write_all(resp.as_bytes());
    false
}

/// The connection request path as the domain of the challenge. A path that would need
/// quoting is replaced by the root.
fn digest_domain(path: &str) -> &str {
    if !path.is_empty()
        && path
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
    {
        path
    } else {
        "/"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirect(status: u16, location: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: BTreeMap::from([("location".to_owned(), location.to_owned())]),
            set_cookies: Vec::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn location_resolves_against_the_session_url() {
        let base = parse_url("https://acs.example.invalid:7547/cwmp/acs?token=1").unwrap();
        let rel = base.resolve("node2?x=1").unwrap();
        assert!(rel.is_https);
        assert_eq!(rel.host, "acs.example.invalid");
        assert_eq!(rel.port, 7547);
        assert_eq!(rel.path_query, "/cwmp/node2?x=1");
        assert_eq!(rel.without_query(), "https://acs.example.invalid:7547/cwmp/node2");

        let abs = base.resolve("http://[2001:db8::1]:8080/a?b=c").unwrap();
        assert!(!abs.is_https);
        assert_eq!(abs.host, "[2001:db8::1]");
        assert_eq!(abs.port, 8080);
        assert_eq!(abs.path_query, "/a?b=c");
        assert_eq!(
            abs.resolve("/d").unwrap().without_query(),
            "http://[2001:db8::1]:8080/d"
        );
        assert!(base.resolve("ftp://acs.example.invalid/").is_none());
    }

    #[test]
    fn redirect_stays_on_https_and_drops_cookies_of_another_host() {
        let log = std::path::PathBuf::from(format!(
            "/tmp/tr069-fake-test-redirect-{}.log",
            std::process::id()
        ));
        let mut client = AcsHttpClient::new(
            "https://acs.example.invalid/cwmp/acs?token=1",
            "",
            "",
            false,
            InterfaceRuntime::default(),
            AuditLogger::new(&log),
        )
        .unwrap();
        client.cookies.insert("SID".to_owned(), "1".to_owned());

        client.follow_redirect(&redirect(307, "node2")).unwrap();
        assert_eq!(client.url.path_query, "/cwmp/node2");
        assert_eq!(client.cookies.len(), 1);

        client
            .follow_redirect(&redirect(302, "https://acs2.example.invalid:8443/acs"))
            .unwrap();
        assert_eq!(client.url.host, "acs2.example.invalid");
        assert_eq!(client.url.port, 8443);
        assert!(client.cookies.is_empty());

        let err = client
            .follow_redirect(&redirect(301, "http://acs2.example.invalid/acs"))
            .unwrap_err();
        assert!(err.to_string().contains("https session to http"), "{err}");
        assert!(client.follow_redirect(&redirect(302, "")).is_err());
        assert_eq!(client.redirects, 2);
        assert_eq!(client.url.port, 8443);

        let entries = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(
            entries.contains(
                "ACS redirected the session to https://acs.example.invalid:443/cwmp/node2"
            ),
            "{entries}"
        );
        assert!(!entries.contains("token"), "{entries}");
        let _ = std::fs::remove_file(&log);
    }
}
