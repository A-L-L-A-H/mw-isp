//! RouterOS v6/v7 `.rsc` provisioning script generator.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum RouterOsVersion {
    #[serde(rename = "v6")]
    V6,
    #[serde(rename = "v7")]
    V7,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VpnPeer {
    /// "wireguard" or "tailscale"
    pub kind: String,
    pub public_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_address: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MikrotikConfigRequest {
    pub routeros_version: RouterOsVersion,
    pub radius_server: String,
    pub shared_secret: String,
    pub pppoe_profile: Option<String>,
    pub pppoe_local_address: Option<String>,
    pub pppoe_remote_pool: Option<String>,
    #[serde(default)]
    pub walled_garden: Vec<String>,
    pub vpn_peer: Option<VpnPeer>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("invalid radius_server: {0}")]
    InvalidServer(String),
    #[error("shared_secret must be 8-128 printable characters without quotes or backslashes")]
    InvalidSecret,
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid vpn peer: {0}")]
    InvalidPeer(String),
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/' | ':' | '=' | '+' | '*'))
}

pub fn generate_rsc(req: &MikrotikConfigRequest) -> Result<String, ConfigError> {
    if !safe_token(&req.radius_server) {
        return Err(ConfigError::InvalidServer(req.radius_server.clone()));
    }
    let secret_ok = (8..=128).contains(&req.shared_secret.len())
        && req
            .shared_secret
            .chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '\\' | '$'));
    if !secret_ok {
        return Err(ConfigError::InvalidSecret);
    }
    let profile = req.pppoe_profile.as_deref().unwrap_or("mw-pppoe");
    let local = req.pppoe_local_address.as_deref().unwrap_or("10.255.0.1");
    let pool = req.pppoe_remote_pool.as_deref().unwrap_or("mw-pool");
    for value in [profile, local, pool] {
        if !safe_token(value) {
            return Err(ConfigError::InvalidIdentifier(value.to_string()));
        }
    }
    for host in &req.walled_garden {
        if !safe_token(host) {
            return Err(ConfigError::InvalidIdentifier(host.clone()));
        }
    }

    let version = match req.routeros_version {
        RouterOsVersion::V6 => "v6",
        RouterOsVersion::V7 => "v7",
    };
    let mut out = String::new();
    out.push_str(&format!("# MoonWitness ISP RouterOS {version} provisioning\n"));
    out.push_str(&format!(
        "/radius add service=ppp,hotspot address={} secret=\"{}\" authentication-port=1812 accounting-port=1813 timeout=3s comment=moonwitness\n",
        req.radius_server, req.shared_secret
    ));
    out.push_str("/radius incoming set accept=yes port=3799\n");
    out.push_str(&format!(
        "/ip pool add name={pool} ranges=10.255.0.2-10.255.255.254\n"
    ));
    out.push_str(&format!(
        "/ppp profile add name={profile} local-address={local} remote-address={pool} use-encryption=yes\n"
    ));
    out.push_str("/ppp aaa set use-radius=yes accounting=yes interim-update=5m\n");
    out.push_str("/ip hotspot profile set [find default=yes] use-radius=yes radius-accounting=yes\n");
    for host in &req.walled_garden {
        out.push_str(&format!("/ip hotspot walled-garden add dst-host={host} action=allow\n"));
    }
    if let Some(peer) = &req.vpn_peer {
        match peer.kind.as_str() {
            "wireguard" => {
                let key = peer.public_key.as_deref().unwrap_or_default();
                let allowed = peer.allowed_address.as_deref().unwrap_or("10.200.0.0/24");
                if !safe_token(key) || !safe_token(allowed) {
                    return Err(ConfigError::InvalidPeer("wireguard key/allowed address".into()));
                }
                out.push_str("/interface wireguard add name=wg-mw listen-port=13231\n");
                let endpoint = match &peer.endpoint {
                    Some(ep) if safe_token(ep) => match ep.rsplit_once(':') {
                        Some((host, port)) => {
                            format!(" endpoint-address={host} endpoint-port={port}")
                        }
                        None => format!(" endpoint-address={ep}"),
                    },
                    Some(ep) => return Err(ConfigError::InvalidPeer(ep.clone())),
                    None => String::new(),
                };
                out.push_str(&format!(
                    "/interface wireguard peers add interface=wg-mw public-key=\"{key}\" allowed-address={allowed}{endpoint}\n"
                ));
            }
            "tailscale" => {
                if req.routeros_version == RouterOsVersion::V6 {
                    return Err(ConfigError::InvalidPeer("tailscale requires RouterOS v7 container".into()));
                }
                out.push_str("/container add remote-image=tailscale/tailscale:latest interface=veth-ts root-dir=disk1/tailscale start-on-boot=yes\n");
            }
            other => return Err(ConfigError::InvalidPeer(other.to_string())),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(version: RouterOsVersion) -> MikrotikConfigRequest {
        MikrotikConfigRequest {
            routeros_version: version,
            radius_server: "203.0.113.10".into(),
            shared_secret: "s3cretvalue".into(),
            pppoe_profile: None,
            pppoe_local_address: None,
            pppoe_remote_pool: None,
            walled_garden: vec!["pay.example.com".into()],
            vpn_peer: None,
        }
    }

    #[test]
    fn emits_radius_ports_and_coa() {
        let rsc = generate_rsc(&base(RouterOsVersion::V7)).unwrap();
        assert!(rsc.contains("authentication-port=1812"));
        assert!(rsc.contains("accounting-port=1813"));
        assert!(rsc.contains("/radius incoming set accept=yes port=3799"));
        assert!(rsc.contains("secret=\"s3cretvalue\""));
        assert!(rsc.contains("walled-garden add dst-host=pay.example.com"));
        assert!(rsc.contains("/ppp profile add name=mw-pppoe"));
    }

    #[test]
    fn rejects_injection() {
        let mut req = base(RouterOsVersion::V6);
        req.radius_server = "1.1.1.1; /system reset".into();
        assert!(generate_rsc(&req).is_err());
        let mut req = base(RouterOsVersion::V6);
        req.shared_secret = "bad\"secret1".into();
        assert_eq!(generate_rsc(&req), Err(ConfigError::InvalidSecret));
    }

    #[test]
    fn wireguard_peer_and_tailscale_version_gate() {
        let mut req = base(RouterOsVersion::V7);
        req.vpn_peer = Some(VpnPeer {
            kind: "wireguard".into(),
            public_key: Some("abc123PUBKEY=".into()),
            endpoint: Some("vpn.example.com:51820".into()),
            allowed_address: None,
        });
        let rsc = generate_rsc(&req).unwrap();
        assert!(rsc.contains("endpoint-address=vpn.example.com endpoint-port=51820"));
        req.vpn_peer = Some(VpnPeer {
            kind: "tailscale".into(),
            public_key: None,
            endpoint: None,
            allowed_address: None,
        });
        assert!(generate_rsc(&req).unwrap().contains("tailscale/tailscale"));
        req.routeros_version = RouterOsVersion::V6;
        assert!(generate_rsc(&req).is_err());
    }
}
