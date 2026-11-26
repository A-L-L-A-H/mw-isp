//! Indonesian FTTx Suite:
//! - DNS TrustPositif Policy Matcher (`TrustPositifMatcher`)
//! - Isolir Subscriber Captive State Evaluator (`IsolirPolicy`)
//! - TR-069 GenieACS Inform Webhook Parser (`parse_acs_inform`)

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

// ============================================================================
// 1. DNS TrustPositif Policy Matcher
// ============================================================================

/// Policy category aligned with Kominfo TrustPositif DNS filtering buckets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustPositifCategory {
    Gambling,
    Pornography,
    Phishing,
    Malware,
    Fraud,
    Custom(String),
}

/// Rule entry configuring a blocked or allowed domain suffix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPositifRule {
    pub domain: String,
    pub category: TrustPositifCategory,
    #[serde(default)]
    pub allow: bool,
}

/// Evaluation verdict for a queried domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPositifDecision {
    pub normalized_domain: String,
    pub blocked: bool,
    pub matched_rule: Option<String>,
    pub category: Option<TrustPositifCategory>,
}

/// Fast suffix-based DNS TrustPositif policy matcher.
///
/// Exact and subdomain matches are resolved in O(labels) time using hash lookups
/// over normalized domain suffixes. Explicit allow rules take precedence over
/// block rules.
#[derive(Debug, Clone, Default)]
pub struct TrustPositifMatcher {
    blocked_suffixes: HashMap<String, TrustPositifCategory>,
    allowed_suffixes: HashSet<String>,
}

impl TrustPositifMatcher {
    /// Create an empty matcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a matcher from a slice of policy rules.
    pub fn from_rules(rules: &[TrustPositifRule]) -> Self {
        let mut matcher = Self::new();
        for rule in rules {
            if rule.allow {
                matcher.add_allow(&rule.domain);
            } else {
                matcher.add_block(&rule.domain, rule.category.clone());
            }
        }
        matcher
    }

    /// Normalize a domain or wildcard pattern (`*.example.com.` -> `example.com`).
    pub fn normalize_domain(raw: &str) -> String {
        let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        let without_wildcard = trimmed
            .strip_prefix("*.")
            .or_else(|| trimmed.strip_prefix('.'))
            .unwrap_or(&trimmed);
        without_wildcard.to_string()
    }

    /// Add a blocked domain suffix (matches exact domain and all subdomains).
    pub fn add_block(&mut self, domain: &str, category: TrustPositifCategory) {
        let normalized = Self::normalize_domain(domain);
        if !normalized.is_empty() {
            self.blocked_suffixes.insert(normalized, category);
        }
    }

    /// Add an allow-list override suffix (takes precedence over block rules).
    pub fn add_allow(&mut self, domain: &str) {
        let normalized = Self::normalize_domain(domain);
        if !normalized.is_empty() {
            self.allowed_suffixes.insert(normalized);
        }
    }

    /// Evaluate a DNS query domain against the configured policy.
    pub fn evaluate(&self, domain: &str) -> TrustPositifDecision {
        let normalized = Self::normalize_domain(domain);
        if normalized.is_empty() {
            return TrustPositifDecision {
                normalized_domain: normalized,
                blocked: false,
                matched_rule: None,
                category: None,
            };
        }

        // Check allow-list overrides first across all parent suffixes.
        for suffix in domain_suffixes(&normalized) {
            if self.allowed_suffixes.contains(suffix) {
                return TrustPositifDecision {
                    normalized_domain: normalized.clone(),
                    blocked: false,
                    matched_rule: Some(suffix.to_string()),
                    category: None,
                };
            }
        }

        // Check block-list across all parent suffixes (most specific first).
        for suffix in domain_suffixes(&normalized) {
            if let Some(category) = self.blocked_suffixes.get(suffix) {
                return TrustPositifDecision {
                    normalized_domain: normalized.clone(),
                    blocked: true,
                    matched_rule: Some(suffix.to_string()),
                    category: Some(category.clone()),
                };
            }
        }

        TrustPositifDecision {
            normalized_domain: normalized,
            blocked: false,
            matched_rule: None,
            category: None,
        }
    }
}

fn domain_suffixes(normalized: &str) -> Vec<&str> {
    let mut suffixes = Vec::new();
    let mut current = normalized;
    loop {
        suffixes.push(current);
        match current.find('.') {
            Some(dot_idx) if dot_idx + 1 < current.len() => {
                current = &current[dot_idx + 1..];
            }
            _ => break,
        }
    }
    suffixes
}

// ============================================================================
// 2. Isolir Subscriber Captive State Evaluator
// ============================================================================

/// Operational billing/provisioning state of a PPPoE subscriber.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriberBillingState {
    Active,
    Suspended,
    Overdue,
    Terminated,
}

/// Input snapshot for evaluating whether a subscriber should be redirected to Isolir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolirSubscriberInput {
    pub username: String,
    pub state: SubscriberBillingState,
    pub bytes_used: u64,
    pub quota_bytes: Option<u64>,
    #[serde(default)]
    pub grace_period_active: bool,
}

/// Reason a subscriber is placed into captive Isolir state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolirReason {
    Suspended,
    OverdueInvoice,
    QuotaExceeded,
    Terminated,
}

impl IsolirReason {
    pub fn as_query_code(&self) -> &'static str {
        match self {
            Self::Suspended => "suspended",
            Self::OverdueInvoice => "overdue_invoice",
            Self::QuotaExceeded => "quota_exceeded",
            Self::Terminated => "terminated",
        }
    }

    pub fn http_status_reason(&self) -> &'static str {
        match self {
            Self::Suspended => "PPPoE subscriber suspended - redirected to Isolir captive portal",
            Self::OverdueInvoice => {
                "PPPoE subscriber invoice overdue - redirected to Isolir billing portal"
            }
            Self::QuotaExceeded => {
                "PPPoE subscriber FUP/quota exceeded - redirected to Isolir top-up portal"
            }
            Self::Terminated => "PPPoE subscriber terminated - access isolated",
        }
    }
}

/// Pure-Rust Isolir captive portal evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolirEvaluation {
    pub isolated: bool,
    pub http_status: u16,
    pub http_reason: String,
    pub redirect_target: Option<String>,
    pub reason: Option<IsolirReason>,
}

/// Configurable Isolir captive portal redirect policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolirPolicy {
    pub captive_portal_url: String,
    pub redirect_http_status: u16,
}

impl Default for IsolirPolicy {
    fn default() -> Self {
        Self {
            captive_portal_url: "http://isolir.isp.local/portal".to_string(),
            redirect_http_status: 307,
        }
    }
}

impl IsolirPolicy {
    pub fn new(captive_portal_url: impl Into<String>) -> Self {
        Self {
            captive_portal_url: captive_portal_url.into(),
            redirect_http_status: 307,
        }
    }

    /// Evaluate a subscriber snapshot and return captive redirect instructions if isolated.
    pub fn evaluate(&self, input: &IsolirSubscriberInput) -> IsolirEvaluation {
        let reason = match input.state {
            SubscriberBillingState::Terminated => Some(IsolirReason::Terminated),
            SubscriberBillingState::Suspended => Some(IsolirReason::Suspended),
            SubscriberBillingState::Overdue if !input.grace_period_active => {
                Some(IsolirReason::OverdueInvoice)
            }
            SubscriberBillingState::Active | SubscriberBillingState::Overdue => {
                match input.quota_bytes {
                    Some(limit) if limit > 0 && input.bytes_used >= limit => {
                        Some(IsolirReason::QuotaExceeded)
                    }
                    _ => None,
                }
            }
        };

        match reason {
            Some(isolir_reason) => {
                let base = self.captive_portal_url.trim_end_matches('?');
                let separator = if base.contains('?') { '&' } else { '?' };
                let redirect_target = format!(
                    "{base}{separator}user={}&reason={}",
                    encode_query_component(&input.username),
                    isolir_reason.as_query_code()
                );
                IsolirEvaluation {
                    isolated: true,
                    http_status: self.redirect_http_status,
                    http_reason: isolir_reason.http_status_reason().to_string(),
                    redirect_target: Some(redirect_target),
                    reason: Some(isolir_reason),
                }
            }
            None => IsolirEvaluation {
                isolated: false,
                http_status: 200,
                http_reason: "OK - subscriber active".to_string(),
                redirect_target: None,
                reason: None,
            },
        }
    }
}

fn encode_query_component(raw: &str) -> String {
    let mut encoded = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

// ============================================================================
// 3. TR-069 GenieACS Inform Webhook Parser
// ============================================================================

/// Normalized CPE telemetry extracted from a GenieACS Inform webhook payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcsInformDevice {
    pub device_id: Option<String>,
    pub serial_number: String,
    pub oui: String,
    pub product_class: Option<String>,
    pub firmware_version: Option<String>,
    pub optical_rx_power_dbm: Option<f64>,
    pub lan_ip: Option<String>,
    pub wan_ip: Option<String>,
}

/// Errors returned when parsing a GenieACS Inform JSON payload.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AcsInformError {
    #[error("invalid JSON payload: {0}")]
    InvalidJson(String),
    #[error("ACS inform payload must be a JSON object")]
    NotAnObject,
    #[error("missing required device serial number")]
    MissingSerialNumber,
    #[error("missing required device OUI")]
    MissingOui,
}

/// Parse and normalize a TR-069 GenieACS Inform webhook JSON payload.
pub fn parse_acs_inform(payload: &str) -> Result<AcsInformDevice, AcsInformError> {
    let root: Value =
        serde_json::from_str(payload).map_err(|err| AcsInformError::InvalidJson(err.to_string()))?;
    parse_acs_inform_value(&root)
}

/// Parse and normalize an already-deserialized GenieACS Inform JSON [`Value`].
pub fn parse_acs_inform_value(root: &Value) -> Result<AcsInformDevice, AcsInformError> {
    if !root.is_object() {
        return Err(AcsInformError::NotAnObject);
    }

    let device_id = extract_string(root, &[&["_id"], &["device_id"]]);

    let serial_number = extract_string(
        root,
        &[
            &["_deviceId", "_SerialNumber"],
            &["InternetGatewayDevice", "DeviceInfo", "SerialNumber", "_value"],
            &["InternetGatewayDevice", "DeviceInfo", "SerialNumber"],
            &["Device", "DeviceInfo", "SerialNumber", "_value"],
            &["Device", "DeviceInfo", "SerialNumber"],
            &["serial_number"],
        ],
    )
    .ok_or(AcsInformError::MissingSerialNumber)?;

    let oui = extract_string(
        root,
        &[
            &["_deviceId", "_OUI"],
            &["InternetGatewayDevice", "DeviceInfo", "ManufacturerOUI", "_value"],
            &["InternetGatewayDevice", "DeviceInfo", "ManufacturerOUI"],
            &["Device", "DeviceInfo", "ManufacturerOUI", "_value"],
            &["Device", "DeviceInfo", "ManufacturerOUI"],
            &["oui"],
        ],
    )
    .ok_or(AcsInformError::MissingOui)?;

    let product_class = extract_string(
        root,
        &[
            &["_deviceId", "_ProductClass"],
            &["InternetGatewayDevice", "DeviceInfo", "ProductClass", "_value"],
            &["Device", "DeviceInfo", "ProductClass", "_value"],
            &["product_class"],
        ],
    );

    let firmware_version = extract_string(
        root,
        &[
            &["InternetGatewayDevice", "DeviceInfo", "SoftwareVersion", "_value"],
            &["InternetGatewayDevice", "DeviceInfo", "SoftwareVersion"],
            &["Device", "DeviceInfo", "SoftwareVersion", "_value"],
            &["Device", "DeviceInfo", "SoftwareVersion"],
            &["firmware_version"],
        ],
    );

    let optical_rx_power_dbm = extract_f64(
        root,
        &[
            &[
                "InternetGatewayDevice",
                "WANDevice",
                "1",
                "X_GponInterafceConfig",
                "RXPower",
                "_value",
            ],
            &[
                "InternetGatewayDevice",
                "WANDevice",
                "1",
                "X_GPON_InterfaceConfig",
                "RxPower",
                "_value",
            ],
            &[
                "InternetGatewayDevice",
                "WANDevice",
                "1",
                "X_CT-COM_EponInterfaceConfig",
                "RXPower",
                "_value",
            ],
            &["Device", "Optical", "Interface", "1", "RxPower", "_value"],
            &["optical_rx_power_dbm"],
        ],
    );

    let lan_ip = extract_string(
        root,
        &[
            &[
                "InternetGatewayDevice",
                "LANDevice",
                "1",
                "LANHostConfigManagement",
                "IPInterface",
                "1",
                "IPInterfaceIPAddress",
                "_value",
            ],
            &[
                "Device",
                "IP",
                "Interface",
                "1",
                "IPv4Address",
                "1",
                "IPAddress",
                "_value",
            ],
            &["lan_ip"],
        ],
    );

    let wan_ip = extract_string(
        root,
        &[
            &[
                "InternetGatewayDevice",
                "WANDevice",
                "1",
                "WANConnectionDevice",
                "1",
                "WANPPPConnection",
                "1",
                "ExternalIPAddress",
                "_value",
            ],
            &[
                "InternetGatewayDevice",
                "WANDevice",
                "1",
                "WANConnectionDevice",
                "1",
                "WANIPConnection",
                "1",
                "ExternalIPAddress",
                "_value",
            ],
            &[
                "Device",
                "PPP",
                "Interface",
                "1",
                "IPCP",
                "LocalIPAddress",
                "_value",
            ],
            &["wan_ip"],
        ],
    );

    Ok(AcsInformDevice {
        device_id,
        serial_number,
        oui,
        product_class,
        firmware_version,
        optical_rx_power_dbm,
        lan_ip,
        wan_ip,
    })
}

fn lookup_path<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cursor = root;
    for segment in path {
        cursor = cursor.get(*segment)?;
    }
    Some(cursor)
}

fn extract_string(root: &Value, paths: &[&[&str]]) -> Option<String> {
    for path in paths {
        if let Some(val) = lookup_path(root, path) {
            if let Some(s) = val.as_str() {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

fn extract_f64(root: &Value, paths: &[&[&str]]) -> Option<f64> {
    for path in paths {
        if let Some(val) = lookup_path(root, path) {
            if let Some(n) = val.as_f64() {
                return Some(n);
            }
            if let Some(s) = val.as_str() {
                let cleaned = s.trim().trim_end_matches("dBm").trim_end_matches("dbm").trim();
                if let Ok(parsed) = cleaned.parse::<f64>() {
                    return Some(parsed);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trustpositif_blocks_exact_and_wildcard_subdomains() {
        let matcher = TrustPositifMatcher::from_rules(&[
            TrustPositifRule {
                domain: "*.slot-gacor.example".to_string(),
                category: TrustPositifCategory::Gambling,
                allow: false,
            },
            TrustPositifRule {
                domain: "phish.id.".to_string(),
                category: TrustPositifCategory::Phishing,
                allow: false,
            },
            TrustPositifRule {
                domain: "safe.slot-gacor.example".to_string(),
                category: TrustPositifCategory::Gambling,
                allow: true,
            },
        ]);

        let exact = matcher.evaluate("SLOT-GACOR.EXAMPLE.");
        assert!(exact.blocked);
        assert_eq!(exact.category, Some(TrustPositifCategory::Gambling));
        assert_eq!(exact.matched_rule.as_deref(), Some("slot-gacor.example"));

        let sub = matcher.evaluate("cdn.api.phish.id");
        assert!(sub.blocked);
        assert_eq!(sub.category, Some(TrustPositifCategory::Phishing));
        assert_eq!(sub.matched_rule.as_deref(), Some("phish.id"));

        // Sibling suffix must NOT match.
        let sibling = matcher.evaluate("notphish.id");
        assert!(!sibling.blocked);
        assert_eq!(sibling.matched_rule, None);

        // Explicit allow-list override wins over parent block rule.
        let allowed = matcher.evaluate("app.safe.slot-gacor.example");
        assert!(!allowed.blocked);
        assert_eq!(
            allowed.matched_rule.as_deref(),
            Some("safe.slot-gacor.example")
        );
    }

    #[test]
    fn isolir_redirects_suspended_overdue_and_quota_exceeded_subscribers() {
        let policy = IsolirPolicy::new("https://isolir.mw-isp.id/captive");

        let active = policy.evaluate(&IsolirSubscriberInput {
            username: "pelanggan01@isp".to_string(),
            state: SubscriberBillingState::Active,
            bytes_used: 500_000,
            quota_bytes: Some(1_000_000),
            grace_period_active: false,
        });
        assert!(!active.isolated);
        assert_eq!(active.http_status, 200);
        assert_eq!(active.redirect_target, None);

        let suspended = policy.evaluate(&IsolirSubscriberInput {
            username: "pelanggan02@isp".to_string(),
            state: SubscriberBillingState::Suspended,
            bytes_used: 0,
            quota_bytes: None,
            grace_period_active: false,
        });
        assert!(suspended.isolated);
        assert_eq!(suspended.http_status, 307);
        assert_eq!(suspended.reason, Some(IsolirReason::Suspended));
        assert_eq!(
            suspended.redirect_target.as_deref(),
            Some("https://isolir.mw-isp.id/captive?user=pelanggan02%40isp&reason=suspended")
        );

        let quota = policy.evaluate(&IsolirSubscriberInput {
            username: "pelanggan03".to_string(),
            state: SubscriberBillingState::Active,
            bytes_used: 2_000_000,
            quota_bytes: Some(1_000_000),
            grace_period_active: false,
        });
        assert!(quota.isolated);
        assert_eq!(quota.reason, Some(IsolirReason::QuotaExceeded));
        assert!(quota.http_reason.contains("quota exceeded"));

        let overdue_grace = policy.evaluate(&IsolirSubscriberInput {
            username: "pelanggan04".to_string(),
            state: SubscriberBillingState::Overdue,
            bytes_used: 100,
            quota_bytes: None,
            grace_period_active: true,
        });
        assert!(!overdue_grace.isolated);
    }

    #[test]
    fn parse_acs_inform_normalizes_genieacs_tr069_payload() {
        let payload = r#"{
            "_id": "00259E-EG8145V5-4857544312345678",
            "_deviceId": {
                "_OUI": "00259E",
                "_ProductClass": "EG8145V5",
                "_SerialNumber": "4857544312345678"
            },
            "InternetGatewayDevice": {
                "DeviceInfo": {
                    "SoftwareVersion": { "_value": "V5R019C10S350" }
                },
                "LANDevice": {
                    "1": {
                        "LANHostConfigManagement": {
                            "IPInterface": {
                                "1": {
                                    "IPInterfaceIPAddress": { "_value": "192.168.100.1" }
                                }
                            }
                        }
                    }
                },
                "WANDevice": {
                    "1": {
                        "X_GponInterafceConfig": {
                            "RXPower": { "_value": "-19.45 dBm" }
                        },
                        "WANConnectionDevice": {
                            "1": {
                                "WANPPPConnection": {
                                    "1": {
                                        "ExternalIPAddress": { "_value": "103.145.22.10" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;

        let device = parse_acs_inform(payload).expect("valid GenieACS inform");
        assert_eq!(
            device.device_id.as_deref(),
            Some("00259E-EG8145V5-4857544312345678")
        );
        assert_eq!(device.serial_number, "4857544312345678");
        assert_eq!(device.oui, "00259E");
        assert_eq!(device.product_class.as_deref(), Some("EG8145V5"));
        assert_eq!(device.firmware_version.as_deref(), Some("V5R019C10S350"));
        assert_eq!(device.optical_rx_power_dbm, Some(-19.45));
        assert_eq!(device.lan_ip.as_deref(), Some("192.168.100.1"));
        assert_eq!(device.wan_ip.as_deref(), Some("103.145.22.10"));
    }

    #[test]
    fn parse_acs_inform_rejects_missing_required_fields() {
        let missing_serial = r#"{"_deviceId": {"_OUI": "00259E"}}"#;
        assert_eq!(
            parse_acs_inform(missing_serial),
            Err(AcsInformError::MissingSerialNumber)
        );

        let missing_oui = r#"{"_deviceId": {"_SerialNumber": "SN123"}}"#;
        assert_eq!(
            parse_acs_inform(missing_oui),
            Err(AcsInformError::MissingOui)
        );
    }
}
