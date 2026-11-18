// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// ARPHRD_NONE control interfaces reference their PON netdev through iflink.
pub fn parent_interface_mac(interface: &str) -> io::Result<[u8; 6]> {
    let path = parent_interface_path(interface)?;

    parse_mac(&read_trimmed(path.join("address"))?)
}

/// OAM sends from the address the EPON MAC registers with. Drivers without the epon_mac_address
/// attribute register with the parent MAC.
pub fn epon_registration_mac(interface: &str) -> io::Result<[u8; 6]> {
    match parent_xpon_attribute(interface, "epon_mac_address")? {
        Some(path) => parse_mac(&read_trimmed(path)?),
        None => parent_interface_mac(interface),
    }
}

pub fn parent_xpon_attribute(interface: &str, attribute: &str) -> io::Result<Option<PathBuf>> {
    let path = parent_interface_path(interface)?
        .join("xpon")
        .join(attribute);

    Ok(path.is_file().then_some(path))
}

fn parent_interface_path(interface: &str) -> io::Result<PathBuf> {
    let iflink = read_trimmed(format!("/sys/class/net/{interface}/iflink"))?;

    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let ifindex = match read_trimmed(entry.path().join("ifindex")) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if ifindex == iflink {
            return Ok(entry.path());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("parent interface for {interface} was not found"),
    ))
}

fn read_trimmed(path: impl AsRef<Path>) -> io::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn parse_mac(value: &str) -> io::Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    let fields: Vec<&str> = value.split(':').collect();
    if fields.len() != mac.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MAC address",
        ));
    }
    for (destination, field) in mac.iter_mut().zip(fields) {
        *destination = u8::from_str_radix(field, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid MAC address"))?;
    }
    Ok(mac)
}
