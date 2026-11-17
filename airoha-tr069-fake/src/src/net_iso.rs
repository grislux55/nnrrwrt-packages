// SPDX-License-Identifier: GPL-2.0-only

use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, UdpSocket,
};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use serde_json::Value as JsonValue;

/// Longest wait of a listener thread for a connection before it checks its stop flag again.
pub const ACCEPT_POLL: Duration = Duration::from_millis(500);

const IF_INET6_PATH: &str = "/proc/net/if_inet6";
/// Host, link and site scope bits of an if_inet6 line. A global address has none of them.
const IF_INET6_SCOPE_NOT_GLOBAL: u32 = 0x70;
const IF_INET6_FLAG_DADFAILED: u32 = 0x08;
const IF_INET6_FLAG_TENTATIVE: u32 = 0x40;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterfaceRuntime {
    pub ifname: String,
    pub ipv4_addrs: Vec<Ipv4Addr>,
    pub ipv6_addrs: Vec<Ipv6Addr>,
    pub ipv6_tentative: Vec<Ipv6Addr>,
    pub dns_servers: Vec<IpAddr>,
}

impl InterfaceRuntime {
    /// Reads the addresses of `ifname` from the kernel. `dns_servers` stays empty: the caller
    /// that opens a session adds them with with_dns_servers().
    pub fn inspect(ifname: &str) -> Self {
        let mut rt = Self {
            ifname: ifname.to_owned(),
            ..Default::default()
        };
        if ifname.is_empty() {
            return rt;
        }
        let (ipv4_addrs, ipv6_order) = read_device_addrs(ifname);
        rt.ipv4_addrs = ipv4_addrs;
        (rt.ipv6_addrs, rt.ipv6_tentative) = read_ipv6_addrs(ifname, &ipv6_order);
        rt
    }

    /// Returns a copy that also holds the DNS servers netifd reports for the two management
    /// interfaces, read with two `ubus` calls.
    pub fn with_dns_servers(&self) -> Self {
        let mut rt = self.clone();
        if rt.ifname.is_empty() {
            return rt;
        }
        rt.dns_servers = read_ubus_dns("tr069");
        for dns in read_ubus_dns("tr069_6") {
            if !rt.dns_servers.contains(&dns) {
                rt.dns_servers.push(dns);
            }
        }
        rt
    }

    pub fn conn_req_bind_addrs(&self, port: u16) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();
        for v4 in &self.ipv4_addrs {
            if !v4.is_unspecified() {
                addrs.push(SocketAddr::V4(SocketAddrV4::new(*v4, port)));
            }
        }
        for v6 in &self.ipv6_addrs {
            if !v6.is_unspecified() && !is_ipv6_link_local(*v6) {
                addrs.push(SocketAddr::V6(SocketAddrV6::new(*v6, port, 0, 0)));
            }
        }
        addrs
    }
}

fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// IPv4 and IPv6 addresses of `ifname` as getifaddrs() lists them, which is the order of
/// `ip addr show dev <ifname>`. Loopback IPv4 addresses are left out.
///
/// netifd adds every address with scope global, so the IPv4 list is the set that
/// `ip -4 addr show dev <ifname> scope global` prints for an interface it manages. The IPv6
/// list carries neither scope nor DAD state and only orders what read_ipv6_addrs() returns.
fn read_device_addrs(ifname: &str) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs() stores the head of a list that stays valid until freeifaddrs().
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return (ipv4, ipv6);
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list returned above.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes();
        // An address label such as "eth0:1" names its device ahead of the colon.
        if name.split(|b| *b == b':').next() != Some(ifname.as_bytes()) {
            continue;
        }
        // SAFETY: ifa_addr points to at least a sockaddr. The copy needs no alignment.
        let sa = unsafe { std::ptr::read_unaligned(ifa.ifa_addr) };
        match libc::c_int::from(sa.sa_family) {
            libc::AF_INET => {
                let sin = ifa.ifa_addr.cast::<libc::sockaddr_in>();
                // SAFETY: an AF_INET entry holds a sockaddr_in. The copy needs no alignment.
                let sin = unsafe { std::ptr::read_unaligned(sin) };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if !ip.is_loopback() && !ipv4.contains(&ip) {
                    ipv4.push(ip);
                }
            }
            libc::AF_INET6 => {
                let sin6 = ifa.ifa_addr.cast::<libc::sockaddr_in6>();
                // SAFETY: an AF_INET6 entry holds a sockaddr_in6. The copy needs no alignment.
                let sin6 = unsafe { std::ptr::read_unaligned(sin6) };
                ipv6.push(Ipv6Addr::from(sin6.sin6_addr.s6_addr));
            }
            _ => {}
        }
    }
    // SAFETY: `head` came from getifaddrs() and no reference into the list is left.
    unsafe { libc::freeifaddrs(head) };
    (ipv4, ipv6)
}

/// Global IPv6 addresses of `ifname`, usable and DAD-tentative, in the order of
/// `device_order`. /proc/net/if_inet6 lists them by hash bucket, and the first usable address
/// is the source address of a session.
fn read_ipv6_addrs(ifname: &str, device_order: &[Ipv6Addr]) -> (Vec<Ipv6Addr>, Vec<Ipv6Addr>) {
    let Ok(text) = std::fs::read_to_string(IF_INET6_PATH) else {
        return (Vec::new(), Vec::new());
    };
    let (mut usable, mut tentative) = parse_if_inet6(&text, ifname);
    sort_by_device_order(&mut usable, device_order);
    sort_by_device_order(&mut tentative, device_order);
    (usable, tentative)
}

/// Sorts `addrs` into the order of `device_order`. Addresses that it does not hold keep
/// their order behind the others.
fn sort_by_device_order(addrs: &mut [Ipv6Addr], device_order: &[Ipv6Addr]) {
    addrs.sort_by_key(|ip| {
        device_order
            .iter()
            .position(|known| known == ip)
            .unwrap_or(device_order.len())
    });
}

/// Splits the global addresses that /proc/net/if_inet6 lists for `ifname` into usable and
/// DAD-tentative ones and drops those that failed DAD.
///
/// A line holds the address as 32 hex digits, then the interface index, the prefix length,
/// the scope and the flags in hex, then the interface name.
pub fn parse_if_inet6(text: &str, ifname: &str) -> (Vec<Ipv6Addr>, Vec<Ipv6Addr>) {
    let mut usable = Vec::new();
    let mut tentative = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let &[addr, _ifindex, _prefix_len, scope, flags, name] = fields.as_slice() else {
            continue;
        };
        if name != ifname || addr.len() != 32 {
            continue;
        }
        let (Ok(addr), Ok(scope), Ok(flags)) = (
            u128::from_str_radix(addr, 16),
            u32::from_str_radix(scope, 16),
            u32::from_str_radix(flags, 16),
        ) else {
            continue;
        };
        if scope & IF_INET6_SCOPE_NOT_GLOBAL != 0 || flags & IF_INET6_FLAG_DADFAILED != 0 {
            continue;
        }
        if flags & IF_INET6_FLAG_TENTATIVE != 0 {
            tentative.push(Ipv6Addr::from(addr));
        } else {
            usable.push(Ipv6Addr::from(addr));
        }
    }
    (usable, tentative)
}

fn read_ubus_dns(iface: &str) -> Vec<IpAddr> {
    let service = format!("network.interface.{iface}");
    let Ok(out) = Command::new("ubus").args(["call", &service, "status"]).output() else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let Ok(status) = serde_json::from_str::<JsonValue>(&text) else {
        return Vec::new();
    };
    parse_ubus_dns(&status)
}

/// Returns the DNS servers in the reply of `ubus call network.interface.<name> status`.
///
/// tr069-fake-apply sets `peerdns 0` on both management interfaces. netifd then keeps the
/// servers of a DHCP or DHCPv6 lease out of the system resolver and lists them under
/// `inactive`; the top-level list holds the servers of the `dns` option only.
pub fn parse_ubus_dns(status: &JsonValue) -> Vec<IpAddr> {
    let lists = [
        status.get("dns-server"),
        status.get("inactive").and_then(|inactive| inactive.get("dns-server")),
    ];
    let mut servers = Vec::new();
    for item in lists.into_iter().flatten().filter_map(JsonValue::as_array).flatten() {
        let Some(ip) = item.as_str().and_then(|text| text.parse::<IpAddr>().ok()) else {
            continue;
        };
        if !servers.contains(&ip) {
            servers.push(ip);
        }
    }
    servers
}

/// Waits until `fd` is readable or `timeout` has passed and tells whether it is readable.
///
/// An interrupted poll() returns at once. Any other poll() failure sleeps for `timeout`, so
/// a loop around this function never spins.
pub fn wait_readable(fd: &impl AsRawFd, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: `pfd` is one valid pollfd for the duration of the call.
    let rc = unsafe { libc::poll(&mut pfd, 1, millis) };
    if rc > 0 {
        return true;
    }
    if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
        std::thread::sleep(timeout);
    }
    false
}

pub fn bind_socket_to_device(fd: libc::c_int, ifname: &str) -> io::Result<()> {
    if ifname.is_empty() || ifname == "lo" {
        return Ok(());
    }
    let c_if = CString::new(ifname)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid ifname"))?;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            c_if.as_ptr() as *const libc::c_void,
            (ifname.len() + 1) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn connect_isolated_tcp(
    host: &str,
    port: u16,
    rt: &InterfaceRuntime,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let addrs = resolve_target_addrs(host, rt, timeout)?;
    let mut last_err = io::Error::new(io::ErrorKind::AddrNotAvailable, "no resolved address");
    for ip in addrs {
        let target = SocketAddr::new(ip, port);
        match connect_single_tcp(target, rt, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = err,
        }
    }
    Err(last_err)
}

fn resolve_if_index(ifname: &str) -> io::Result<u32> {
    if ifname.is_empty() || ifname == "lo" {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "link-local address requires a concrete network interface",
        ));
    }
    let c_if = CString::new(ifname)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid ifname"))?;
    let idx = unsafe { libc::if_nametoindex(c_if.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface not found for link-local scope: {ifname}"),
        ));
    }
    Ok(idx)
}

fn connect_single_tcp(
    mut target: SocketAddr,
    rt: &InterfaceRuntime,
    timeout: Duration,
) -> io::Result<TcpStream> {
    if let SocketAddr::V6(ref mut v6) = target {
        if is_ipv6_link_local(*v6.ip()) && v6.scope_id() == 0 {
            v6.set_scope_id(resolve_if_index(&rt.ifname)?);
        }
    }
    let domain = match target {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    if !rt.ifname.is_empty() && rt.ifname != "lo" {
        bind_socket_to_device(stream.as_raw_fd(), &rt.ifname)?;
    }
    match target {
        SocketAddr::V4(_) => {
            if let Some(src) = rt.ipv4_addrs.first() {
                bind_raw_addr(stream.as_raw_fd(), SocketAddr::V4(SocketAddrV4::new(*src, 0)))?;
            }
        }
        SocketAddr::V6(v6) => {
            if !is_ipv6_link_local(*v6.ip()) {
                if let Some(src) = rt
                    .ipv6_addrs
                    .iter()
                    .find(|ip| !ip.is_unspecified() && !is_ipv6_link_local(**ip))
                {
                    bind_raw_addr(
                        stream.as_raw_fd(),
                        SocketAddr::V6(SocketAddrV6::new(*src, 0, 0, 0)),
                    )?;
                }
            }
        }
    }
    set_socket_timeout(stream.as_raw_fd(), timeout)?;
    connect_raw(stream.as_raw_fd(), target)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

fn set_socket_timeout(fd: libc::c_int, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as _,
        tv_usec: timeout.subsec_micros() as _,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bind_raw_addr(fd: libc::c_int, addr: SocketAddr) -> io::Result<()> {
    let rc = match addr {
        SocketAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                libc::bind(
                    fd,
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn connect_raw(fd: libc::c_int, addr: SocketAddr) -> io::Result<()> {
    let rc = match addr {
        SocketAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::connect(
                    fd,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                libc::connect(
                    fd,
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn resolve_target_addrs(
    host: &str,
    rt: &InterfaceRuntime,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    let trimmed = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if !rt.dns_servers.is_empty() {
        let mut results = Vec::new();
        for dns in &rt.dns_servers {
            if !rt.ipv6_addrs.is_empty() || matches!(dns, IpAddr::V6(_)) {
                if let Ok(mut v6s) = query_dns_isolated(*dns, trimmed, 28, rt, timeout) {
                    results.append(&mut v6s);
                }
            }
            if !rt.ipv4_addrs.is_empty() || matches!(dns, IpAddr::V4(_)) {
                if let Ok(mut v4s) = query_dns_isolated(*dns, trimmed, 1, rt, timeout) {
                    results.append(&mut v4s);
                }
            }
            if !results.is_empty() {
                return Ok(results);
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("isolated DNS lookup failed for {host}"),
        ));
    }
    if rt.ifname.is_empty() || rt.ifname == "lo" {
        use std::net::ToSocketAddrs;
        let mut addrs = Vec::new();
        for sa in (trimmed, 0).to_socket_addrs()? {
            addrs.push(sa.ip());
        }
        return Ok(addrs);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no isolated DNS servers available on {}", rt.ifname),
    ))
}

fn dns_endpoints_with_port(
    dns_ip: IpAddr,
    port: u16,
    rt: &InterfaceRuntime,
    scope_id: Option<u32>,
) -> io::Result<(SocketAddr, SocketAddr)> {
    match dns_ip {
        IpAddr::V4(v4) => Ok((
            SocketAddr::V4(SocketAddrV4::new(
                *rt.ipv4_addrs.first().unwrap_or(&Ipv4Addr::UNSPECIFIED),
                0,
            )),
            SocketAddr::V4(SocketAddrV4::new(v4, port)),
        )),
        IpAddr::V6(v6) if is_ipv6_link_local(v6) => {
            let resolved_scope = match scope_id {
                Some(idx) if idx != 0 => idx,
                _ => resolve_if_index(&rt.ifname)?,
            };
            let bind_ip = rt
                .ipv6_addrs
                .iter()
                .find(|ip| is_ipv6_link_local(**ip))
                .copied()
                .unwrap_or(Ipv6Addr::UNSPECIFIED);
            let bind_scope = if is_ipv6_link_local(bind_ip) {
                resolved_scope
            } else {
                0
            };
            Ok((
                SocketAddr::V6(SocketAddrV6::new(bind_ip, 0, 0, bind_scope)),
                SocketAddr::V6(SocketAddrV6::new(v6, port, 0, resolved_scope)),
            ))
        }
        IpAddr::V6(v6) => {
            let bind_ip = rt
                .ipv6_addrs
                .iter()
                .find(|ip| !ip.is_unspecified() && !is_ipv6_link_local(**ip))
                .copied()
                .unwrap_or(Ipv6Addr::UNSPECIFIED);
            Ok((
                SocketAddr::V6(SocketAddrV6::new(bind_ip, 0, 0, 0)),
                SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
            ))
        }
    }
}

fn dns_udp_endpoints(
    dns_ip: IpAddr,
    rt: &InterfaceRuntime,
    scope_id: Option<u32>,
) -> io::Result<(SocketAddr, SocketAddr)> {
    dns_endpoints_with_port(dns_ip, 53, rt, scope_id)
}

fn next_dns_txid() -> u16 {
    let mut rnd = [0u8; 2];
    if getrandom::fill(&mut rnd).is_ok() {
        return u16::from_be_bytes(rnd);
    }
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        & 0xffff) as u16
}

enum DnsPacketOutcome {
    Truncated,
    Addrs(Vec<IpAddr>),
    Cname(String),
    Empty,
}

pub fn query_dns_isolated(
    dns_ip: IpAddr,
    host: &str,
    qtype: u16,
    rt: &InterfaceRuntime,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    let (_, dest_addr) = dns_udp_endpoints(dns_ip, rt, None)?;
    query_dns_server_addr(dest_addr, host, qtype, rt, timeout)
}

pub fn query_dns_server_addr(
    dns_addr: SocketAddr,
    host: &str,
    qtype: u16,
    rt: &InterfaceRuntime,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    let scope_opt = match dns_addr {
        SocketAddr::V6(v6) if v6.scope_id() != 0 => Some(v6.scope_id()),
        _ => None,
    };
    let (bind_addr, dest_addr) =
        dns_endpoints_with_port(dns_addr.ip(), dns_addr.port(), rt, scope_opt)?;

    let mut target_name = host.trim_end_matches('.').to_owned();
    for _ in 0..=4 {
        let txid = next_dns_txid();
        let query_bytes = build_dns_query(txid, &target_name, qtype)?;
        let outcome = match query_dns_once_udp(bind_addr, dest_addr, &query_bytes, txid, qtype, rt, timeout)? {
            DnsPacketOutcome::Truncated => {
                query_dns_once_tcp(dest_addr, &query_bytes, txid, qtype, rt, timeout)?
            }
            other => other,
        };
        match outcome {
            DnsPacketOutcome::Addrs(addrs) => return Ok(addrs),
            DnsPacketOutcome::Cname(next_host) => {
                let next_clean = next_host.trim_end_matches('.').to_owned();
                if next_clean.is_empty() || next_clean.eq_ignore_ascii_case(&target_name) {
                    return Ok(Vec::new());
                }
                target_name = next_clean;
            }
            DnsPacketOutcome::Empty | DnsPacketOutcome::Truncated => return Ok(Vec::new()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "DNS CNAME chain exceeded maximum depth",
    ))
}

fn query_dns_once_udp(
    bind_addr: SocketAddr,
    dest_addr: SocketAddr,
    query_bytes: &[u8],
    txid: u16,
    qtype: u16,
    rt: &InterfaceRuntime,
    timeout: Duration,
) -> io::Result<DnsPacketOutcome> {
    let sock = UdpSocket::bind(bind_addr)?;
    if !rt.ifname.is_empty() && rt.ifname != "lo" {
        bind_socket_to_device(sock.as_raw_fd(), &rt.ifname)?;
    }
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    sock.send_to(query_bytes, dest_addr)?;
    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf)?;
    parse_dns_packet_outcome(&buf[..n], txid, qtype)
}

fn query_dns_once_tcp(
    dest_addr: SocketAddr,
    query_bytes: &[u8],
    txid: u16,
    qtype: u16,
    rt: &InterfaceRuntime,
    timeout: Duration,
) -> io::Result<DnsPacketOutcome> {
    let len_u16 = u16::try_from(query_bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS query too large for TCP"))?;
    let mut tcp = connect_single_tcp(dest_addr, rt, timeout)?;
    tcp.write_all(&len_u16.to_be_bytes())?;
    tcp.write_all(query_bytes)?;
    tcp.flush()?;

    let mut len_buf = [0u8; 2];
    tcp.read_exact(&mut len_buf)?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short TCP DNS packet",
        ));
    }
    let mut resp_buf = vec![0u8; resp_len];
    tcp.read_exact(&mut resp_buf)?;
    parse_dns_packet_outcome(&resp_buf, txid, qtype)
}

pub fn build_dns_query(txid: u16, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let clean = host.trim_end_matches('.');
    if clean.is_empty()
        || clean
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid DNS label",
        ));
    }
    let fqdn = format!("{clean}.");
    let name = Name::from_ascii(&fqdn)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid DNS name: {e}")))?;
    let mut query = Query::query(name, RecordType::from(qtype));
    query.set_query_class(DNSClass::IN);

    let mut msg = Message::new();
    msg.set_id(txid);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(query);
    msg.to_bytes()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("DNS encode error: {e}")))
}

fn parse_dns_packet_outcome(
    buf: &[u8],
    expected_txid: u16,
    expected_qtype: u16,
) -> io::Result<DnsPacketOutcome> {
    let msg = Message::from_bytes(buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("DNS decode error: {e}")))?;
    if msg.id() != expected_txid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS txid mismatch",
        ));
    }
    if msg.truncated() {
        return Ok(DnsPacketOutcome::Truncated);
    }
    match msg.response_code() {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return Ok(DnsPacketOutcome::Empty),
        other => {
            return Err(io::Error::other(format!(
                "DNS server returned response code {other}"
            )))
        }
    }

    let mut current_name: Option<Name> = msg.queries().first().map(|q| q.name().clone());
    let mut saw_cname = false;
    for _ in 0..8 {
        let Some(ref target) = current_name else {
            break;
        };
        let next = msg.answers().iter().find_map(|rec| {
            if rec.name() == target {
                if let Some(RData::CNAME(cname)) = rec.data() {
                    return Some(cname.0.clone());
                }
            }
            None
        });
        if let Some(cname_target) = next {
            if &cname_target == target {
                break;
            }
            current_name = Some(cname_target);
            saw_cname = true;
        } else {
            break;
        }
    }

    let mut addrs = Vec::new();
    for rec in msg.answers() {
        let name_matches = current_name
            .as_ref()
            .map(|target| rec.name() == target)
            .unwrap_or(true);
        if !name_matches {
            continue;
        }
        match (expected_qtype, rec.data()) {
            (1, Some(RData::A(a))) => addrs.push(IpAddr::V4(a.0)),
            (28, Some(RData::AAAA(aaaa))) => addrs.push(IpAddr::V6(aaaa.0)),
            _ => {}
        }
    }
    if !addrs.is_empty() {
        return Ok(DnsPacketOutcome::Addrs(addrs));
    }
    if saw_cname {
        if let Some(cname_target) = current_name {
            return Ok(DnsPacketOutcome::Cname(cname_target.to_ascii()));
        }
    }
    Ok(DnsPacketOutcome::Empty)
}

pub fn parse_dns_response(
    buf: &[u8],
    expected_txid: u16,
    expected_qtype: u16,
) -> io::Result<Vec<IpAddr>> {
    match parse_dns_packet_outcome(buf, expected_txid, expected_qtype)? {
        DnsPacketOutcome::Addrs(addrs) => Ok(addrs),
        DnsPacketOutcome::Truncated | DnsPacketOutcome::Cname(_) | DnsPacketOutcome::Empty => {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn link_local_ipv6_dns_uses_interface_scope_id() {
        let rt = InterfaceRuntime {
            ifname: "eth0.46".to_owned(),
            ipv4_addrs: Vec::new(),
            ipv6_addrs: vec!["2001:db8::10".parse().unwrap()],
            ipv6_tentative: Vec::new(),
            dns_servers: vec!["fe80::1".parse().unwrap()],
        };
        let (bind, dest) =
            dns_udp_endpoints("fe80::1".parse().unwrap(), &rt, Some(7)).expect("endpoints");
        assert_eq!(
            bind,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        );
        assert_eq!(
            dest,
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 7))
        );
    }

    #[test]
    fn link_local_ipv6_dns_binds_local_ll_with_same_scope_when_present() {
        let rt = InterfaceRuntime {
            ifname: "eth0.46".to_owned(),
            ipv4_addrs: Vec::new(),
            ipv6_addrs: vec![
                "2001:db8::10".parse().unwrap(),
                "fe80::2".parse().unwrap(),
            ],
            ipv6_tentative: Vec::new(),
            dns_servers: Vec::new(),
        };
        let (bind, dest) =
            dns_udp_endpoints("fe80::1".parse().unwrap(), &rt, Some(9)).expect("endpoints");
        assert_eq!(
            bind,
            SocketAddr::V6(SocketAddrV6::new("fe80::2".parse().unwrap(), 0, 0, 9))
        );
        assert_eq!(
            dest,
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 9))
        );
    }

    #[test]
    fn link_local_ipv6_dns_requires_concrete_interface() {
        let rt = InterfaceRuntime {
            ifname: String::new(),
            ipv4_addrs: Vec::new(),
            ipv6_addrs: Vec::new(),
            ipv6_tentative: Vec::new(),
            dns_servers: Vec::new(),
        };
        let err = dns_udp_endpoints("fe80::1".parse().unwrap(), &rt, None)
            .expect_err("missing interface should fail");
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
    }

    #[test]
    fn if_inet6_parser_keeps_the_global_addresses_of_one_interface() {
        // Flags: 40 tentative, 48 tentative after a failed DAD, 20 deprecated, 80 permanent.
        // Scopes: 00 global, 10 host, 20 link.
        let text = concat!(
            "00000000000000000000000000000001 01 80 10 80       lo\n",
            "fe80000000000000021122fffe334455 07 40 20 80 tr069-if\n",
            "fd000046000000000000000000000002 07 40 00 40 tr069-if\n",
            "20010db8004600000000000000000002 07 40 00 00 tr069-if\n",
            "20010db8004600000000000000000003 07 40 00 48 tr069-if\n",
            "20010db8004600000000000000000004 07 40 00 20 tr069-if\n",
            "20010db8004600000000000000000005 02 40 00 80     eth0\n",
            "20010db8004600000000000000000006 08 40 00 80 tr069-if2\n",
            "20010db80046 07 40 00 80 tr069-if\n",
            "not an address line\n",
        );
        let (usable, tentative) = parse_if_inet6(text, "tr069-if");
        assert_eq!(
            usable,
            vec![
                "2001:db8:46::2".parse::<Ipv6Addr>().unwrap(),
                "2001:db8:46::4".parse::<Ipv6Addr>().unwrap(),
            ]
        );
        assert_eq!(tentative, vec!["fd00:46::2".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(parse_if_inet6(text, "lo"), (Vec::new(), Vec::new()));
    }

    #[test]
    fn ipv6_addresses_follow_the_device_order() {
        let first: Ipv6Addr = "2001:db8:46::2".parse().unwrap();
        let second: Ipv6Addr = "fd00:46::2".parse().unwrap();
        let third: Ipv6Addr = "2001:db8:46::4".parse().unwrap();
        let mut addrs = vec![first, second, third];
        sort_by_device_order(&mut addrs, &[third, second]);
        assert_eq!(addrs, vec![third, second, first]);
        sort_by_device_order(&mut addrs, &[]);
        assert_eq!(addrs, vec![third, second, first]);
    }

    #[test]
    fn device_addr_reader_skips_ipv4_loopback_and_unknown_interfaces() {
        let (ipv4, _) = read_device_addrs("lo");
        assert!(ipv4.iter().all(|ip| !ip.is_loopback()));
        assert_eq!(read_device_addrs("no-such-if0"), (Vec::new(), Vec::new()));
    }

    #[test]
    fn ubus_dns_parser_reads_the_configured_and_the_lease_servers() {
        // Shape of netifd's reply with `peerdns 0`: the `dns` option at the top level, the
        // servers of the lease under `inactive`.
        let status: JsonValue = serde_json::from_str(
            r#"{
                "up": true,
                "dns-server": ["192.0.2.53"],
                "inactive": {
                    "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "192.0.2.1"}],
                    "dns-server": ["192.0.2.54", "2001:db8:46::53", "192.0.2.53", "none", 7]
                }
            }"#,
        )
        .expect("status");
        let expected: Vec<IpAddr> = vec![
            "192.0.2.53".parse().unwrap(),
            "192.0.2.54".parse().unwrap(),
            "2001:db8:46::53".parse().unwrap(),
        ];
        assert_eq!(parse_ubus_dns(&status), expected);

        let lease_only = serde_json::json!({
            "dns-server": [],
            "inactive": { "dns-server": ["192.0.2.54"] }
        });
        assert_eq!(parse_ubus_dns(&lease_only), expected[1..2].to_vec());
        assert!(parse_ubus_dns(&serde_json::json!({ "up": false })).is_empty());
        assert!(parse_ubus_dns(&serde_json::json!({ "inactive": ["192.0.2.54"] })).is_empty());
        assert!(parse_ubus_dns(&JsonValue::Null).is_empty());
    }

    #[test]
    fn wait_readable_reports_a_pending_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        assert!(!wait_readable(&listener, Duration::from_millis(20)));
        let _client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        assert!(wait_readable(&listener, Duration::from_secs(2)));
    }
}
