//! MikroTik PPPoE/NAS link-down outage detector and localized Indonesian/English
//! WhatsApp notice payload generator.

use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoticeLocale {
    Id,
    En,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutageSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutageKind {
    NasLinkDown,
    PppoeMassDrop,
    HighLatencyDegradation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NasLinkObservation {
    pub nas_name: String,
    pub nas_ip: String,
    pub tower_id: Option<String>,
    pub link_up: bool,
    pub latency_ms: Option<i64>,
    pub heartbeat_age_secs: u64,
    pub active_pppoe_sessions: u64,
    pub dropped_pppoe_sessions: u64,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutageDetectorPolicy {
    pub max_heartbeat_age_secs: u64,
    pub max_latency_ms: i64,
    pub mass_drop_min_sessions: u64,
    pub mass_drop_percent_threshold: u64,
}

impl Default for OutageDetectorPolicy {
    fn default() -> Self {
        Self {
            max_heartbeat_age_secs: 180,
            max_latency_ms: 250,
            mass_drop_min_sessions: 5,
            mass_drop_percent_threshold: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectedOutage {
    pub kind: OutageKind,
    pub severity: OutageSeverity,
    pub nas_name: String,
    pub nas_ip: String,
    pub tower_id: Option<String>,
    pub affected_sessions: u64,
    pub latency_ms: Option<i64>,
    pub heartbeat_age_secs: u64,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoticeRecipient {
    pub phone: String,
    pub locale: NoticeLocale,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhatsAppNoticePayload {
    pub recipient: String,
    pub locale: NoticeLocale,
    pub event_type: OutageKind,
    pub severity: OutageSeverity,
    pub nas_name: String,
    pub nas_ip: String,
    pub tower_id: Option<String>,
    pub affected_sessions: u64,
    pub detected_at: String,
    pub message: String,
}

/// Normalize Indonesian/international phone number or WhatsApp JID (`0812...` -> `62812...`).
pub fn normalize_whatsapp_recipient(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((num, suffix)) = trimmed.split_once('@') {
        let norm = normalize_whatsapp_recipient(num)?;
        if suffix == "s.whatsapp.net" || suffix == "g.us" {
            return Some(format!("{norm}@{suffix}"));
        }
        return None;
    }
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 8 || digits.len() > 16 {
        return None;
    }
    if let Some(rest) = digits.strip_prefix("08") {
        Some(format!("628{rest}"))
    } else if let Some(rest) = digits.strip_prefix('0') {
        Some(format!("62{rest}"))
    } else {
        Some(digits)
    }
}

/// Evaluate a MikroTik NAS/PPPoE observation against the outage detection policy.
pub fn evaluate_nas_observation(
    obs: &NasLinkObservation,
    policy: &OutageDetectorPolicy,
) -> Option<DetectedOutage> {
    let total_sessions = obs.active_pppoe_sessions + obs.dropped_pppoe_sessions;

    // 1. Hard link-down or stale heartbeat or negative (timeout) latency.
    if !obs.link_up
        || obs.heartbeat_age_secs > policy.max_heartbeat_age_secs
        || obs.latency_ms.is_some_and(|ms| ms < 0)
    {
        return Some(DetectedOutage {
            kind: OutageKind::NasLinkDown,
            severity: OutageSeverity::Critical,
            nas_name: obs.nas_name.clone(),
            nas_ip: obs.nas_ip.clone(),
            tower_id: obs.tower_id.clone(),
            affected_sessions: total_sessions.max(obs.dropped_pppoe_sessions),
            latency_ms: obs.latency_ms,
            heartbeat_age_secs: obs.heartbeat_age_secs,
            detected_at: obs.detected_at.clone(),
        });
    }

    // 2. Mass PPPoE drop on an otherwise reachable NAS.
    if obs.dropped_pppoe_sessions >= policy.mass_drop_min_sessions && total_sessions > 0 {
        let drop_pct = (obs.dropped_pppoe_sessions * 100) / total_sessions;
        if drop_pct >= policy.mass_drop_percent_threshold {
            return Some(DetectedOutage {
                kind: OutageKind::PppoeMassDrop,
                severity: OutageSeverity::Critical,
                nas_name: obs.nas_name.clone(),
                nas_ip: obs.nas_ip.clone(),
                tower_id: obs.tower_id.clone(),
                affected_sessions: obs.dropped_pppoe_sessions,
                latency_ms: obs.latency_ms,
                heartbeat_age_secs: obs.heartbeat_age_secs,
                detected_at: obs.detected_at.clone(),
            });
        }
    }

    // 3. High latency degradation warning.
    if let Some(ms) = obs.latency_ms
        && ms > policy.max_latency_ms
    {
        return Some(DetectedOutage {
            kind: OutageKind::HighLatencyDegradation,
            severity: OutageSeverity::Warning,
            nas_name: obs.nas_name.clone(),
            nas_ip: obs.nas_ip.clone(),
            tower_id: obs.tower_id.clone(),
            affected_sessions: obs.active_pppoe_sessions,
            latency_ms: Some(ms),
            heartbeat_age_secs: obs.heartbeat_age_secs,
            detected_at: obs.detected_at.clone(),
        });
    }

    None
}

/// Format a localized Indonesian (`id`) or English (`en`) WhatsApp outage notice message.
pub fn format_whatsapp_notice_message(outage: &DetectedOutage, locale: NoticeLocale) -> String {
    let tower_label = outage.tower_id.as_deref().unwrap_or("MAIN");
    match (locale, outage.kind) {
        (NoticeLocale::Id, OutageKind::NasLinkDown) => format!(
            "[GANGGUAN JARINGAN - KRITIS] Router MikroTik NAS {} ({}) pada Tower {} mengalami terputus koneksi (Link Down) sejak {}. Estimasi sesi PPPoE terdampak: {} pelanggan. Tim teknis kami sedang melakukan penanganan darurat.",
            outage.nas_name,
            outage.nas_ip,
            tower_label,
            outage.detected_at,
            outage.affected_sessions
        ),
        (NoticeLocale::Id, OutageKind::PppoeMassDrop) => format!(
            "[GANGGUAN PPPoE - KRITIS] Terdeteksi putus koneksi PPPoE massal pada Router MikroTik NAS {} ({}) Tower {} pada {}. Sebanyak {} sesi pelanggan terputus. Tim jaringan sedang melakukan pemulihan jalur.",
            outage.nas_name,
            outage.nas_ip,
            tower_label,
            outage.detected_at,
            outage.affected_sessions
        ),
        (NoticeLocale::Id, OutageKind::HighLatencyDegradation) => format!(
            "[PERINGATAN JARINGAN] Latensi tinggi ({} ms) terdeteksi pada Router MikroTik NAS {} ({}) Tower {} pada {}. Sesi aktif terpantau: {} pelanggan.",
            outage.latency_ms.unwrap_or(0),
            outage.nas_name,
            outage.nas_ip,
            tower_label,
            outage.detected_at,
            outage.affected_sessions
        ),
        (NoticeLocale::En, OutageKind::NasLinkDown) => format!(
            "[NETWORK OUTAGE - CRITICAL] MikroTik NAS router {} ({}) at Tower {} is unreachable (Link Down) as of {}. Estimated affected PPPoE sessions: {} subscribers. Our engineering team is actively restoring connectivity.",
            outage.nas_name,
            outage.nas_ip,
            tower_label,
            outage.detected_at,
            outage.affected_sessions
        ),
        (NoticeLocale::En, OutageKind::PppoeMassDrop) => format!(
            "[PPPoE OUTAGE - CRITICAL] Mass PPPoE session drop detected on MikroTik NAS router {} ({}) at Tower {} at {}. {} subscriber sessions disconnected. Network engineers are investigating the fiber/distribution link.",
            outage.nas_name,
            outage.nas_ip,
            tower_label,
            outage.detected_at,
            outage.affected_sessions
        ),
        (NoticeLocale::En, OutageKind::HighLatencyDegradation) => format!(
            "[NETWORK WARNING] High latency ({} ms) detected on MikroTik NAS router {} ({}) at Tower {} at {}. Active monitored sessions: {} subscribers.",
            outage.latency_ms.unwrap_or(0),
            outage.nas_name,
            outage.nas_ip,
            tower_label,
            outage.detected_at,
            outage.affected_sessions
        ),
    }
}

/// Build localized WhatsApp notice payloads for an outage across a list of recipients.
/// If no recipients are supplied, generates default bilingual (`id` and `en`) broadcast payloads.
pub fn build_whatsapp_notices(
    outage: &DetectedOutage,
    recipients: &[NoticeRecipient],
) -> Vec<WhatsAppNoticePayload> {
    if recipients.is_empty() {
        return [NoticeLocale::Id, NoticeLocale::En]
            .into_iter()
            .map(|locale| WhatsAppNoticePayload {
                recipient: "broadcast@g.us".to_string(),
                locale,
                event_type: outage.kind,
                severity: outage.severity,
                nas_name: outage.nas_name.clone(),
                nas_ip: outage.nas_ip.clone(),
                tower_id: outage.tower_id.clone(),
                affected_sessions: outage.affected_sessions,
                detected_at: outage.detected_at.clone(),
                message: format_whatsapp_notice_message(outage, locale),
            })
            .collect();
    }

    recipients
        .iter()
        .filter_map(|r| {
            let normalized = normalize_whatsapp_recipient(&r.phone)?;
            Some(WhatsAppNoticePayload {
                recipient: normalized,
                locale: r.locale,
                event_type: outage.kind,
                severity: outage.severity,
                nas_name: outage.nas_name.clone(),
                nas_ip: outage.nas_ip.clone(),
                tower_id: outage.tower_id.clone(),
                affected_sessions: outage.affected_sessions,
                detected_at: outage.detected_at.clone(),
                message: format_whatsapp_notice_message(outage, r.locale),
            })
        })
        .collect()
}

/// Inspect durable SQLite `nas_clients` and `radius_sessions` for link-down or mass-drop
/// outages (e.g. NAS disabled, negative latency_ms, or mass terminated sessions with
/// RFC 2866 Lost-Carrier=2 / Lost-Service=3 / NAS-Error=9 / NAS-Request=10 / NAS-Reboot=11).
#[allow(clippy::type_complexity)]
pub async fn detect_fleet_outages_from_db(
    pool: &Pool<Sqlite>,
    policy: &OutageDetectorPolicy,
) -> Result<Vec<DetectedOutage>, sqlx::Error> {
    let rows: Vec<(
        String,
        String,
        Option<String>,
        bool,
        Option<i64>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT name, ip_address, tower_id, enabled, latency_ms, last_health_check_at
             FROM nas_clients ORDER BY id ASC",
    )
    .fetch_all(pool)
    .await?;

    let mut outages = Vec::new();
    for (name, ip, tower_id, enabled, latency_ms, last_check) in rows {
        let active_sessions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM radius_sessions WHERE nas_ip = ?1 AND status = 'active'",
        )
        .bind(&ip)
        .fetch_one(pool)
        .await
        .unwrap_or(0);

        // Terminate causes 2 (Lost-Carrier), 3 (Lost-Service), 9 (NAS-Error), 10 (NAS-Request), 11 (NAS-Reboot)
        let dropped_sessions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM radius_sessions
             WHERE nas_ip = ?1 AND status = 'terminated'
               AND COALESCE(terminate_cause, 2) IN (2, 3, 9, 10, 11)",
        )
        .bind(&ip)
        .fetch_one(pool)
        .await
        .unwrap_or(0);

        let link_up = enabled && latency_ms.is_none_or(|ms| ms >= 0);
        let obs = NasLinkObservation {
            nas_name: name,
            nas_ip: ip,
            tower_id,
            link_up,
            latency_ms,
            heartbeat_age_secs: 0,
            active_pppoe_sessions: active_sessions.max(0) as u64,
            dropped_pppoe_sessions: dropped_sessions.max(0) as u64,
            detected_at: last_check.unwrap_or_else(|| "2026-11-27T00:00:00Z".to_string()),
        };
        if let Some(outage) = evaluate_nas_observation(&obs, policy) {
            outages.push(outage);
        }
    }
    Ok(outages)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_observation() -> NasLinkObservation {
        NasLinkObservation {
            nas_name: "CCR2004-Depok-1".to_string(),
            nas_ip: "10.88.1.1".to_string(),
            tower_id: Some("TWR-DPK-01".to_string()),
            link_up: false,
            latency_ms: None,
            heartbeat_age_secs: 300,
            active_pppoe_sessions: 0,
            dropped_pppoe_sessions: 42,
            detected_at: "2026-11-27T09:30:00Z".to_string(),
        }
    }

    #[test]
    fn detects_nas_link_down_and_generates_localized_id_and_en_whatsapp_notices() {
        let policy = OutageDetectorPolicy::default();
        let obs = sample_observation();
        let outage = evaluate_nas_observation(&obs, &policy).expect("expected link down outage");
        assert_eq!(outage.kind, OutageKind::NasLinkDown);
        assert_eq!(outage.severity, OutageSeverity::Critical);
        assert_eq!(outage.affected_sessions, 42);

        let recipients = vec![
            NoticeRecipient {
                phone: "0812-3456-7890".to_string(),
                locale: NoticeLocale::Id,
            },
            NoticeRecipient {
                phone: "+62 811 9988 7766".to_string(),
                locale: NoticeLocale::En,
            },
        ];
        let notices = build_whatsapp_notices(&outage, &recipients);
        assert_eq!(notices.len(), 2);

        let id_notice = &notices[0];
        assert_eq!(id_notice.recipient, "6281234567890");
        assert_eq!(id_notice.locale, NoticeLocale::Id);
        assert!(id_notice.message.contains("[GANGGUAN JARINGAN - KRITIS]"));
        assert!(id_notice.message.contains("CCR2004-Depok-1 (10.88.1.1)"));
        assert!(id_notice.message.contains("TWR-DPK-01"));
        assert!(id_notice.message.contains("42 pelanggan"));

        let en_notice = &notices[1];
        assert_eq!(en_notice.recipient, "6281199887766");
        assert_eq!(en_notice.locale, NoticeLocale::En);
        assert!(en_notice.message.contains("[NETWORK OUTAGE - CRITICAL]"));
        assert!(en_notice.message.contains("CCR2004-Depok-1 (10.88.1.1)"));
        assert!(en_notice.message.contains("TWR-DPK-01"));
        assert!(en_notice.message.contains("42 subscribers"));
    }

    #[test]
    fn detects_pppoe_mass_drop_and_high_latency() {
        let policy = OutageDetectorPolicy::default();

        // Mass PPPoE drop (30 dropped out of 40 total = 75% >= 50%)
        let mass_drop_obs = NasLinkObservation {
            nas_name: "RB5009-Bogor".to_string(),
            nas_ip: "10.88.2.1".to_string(),
            tower_id: Some("TWR-BGR-02".to_string()),
            link_up: true,
            latency_ms: Some(15),
            heartbeat_age_secs: 10,
            active_pppoe_sessions: 10,
            dropped_pppoe_sessions: 30,
            detected_at: "2026-11-27T09:40:00Z".to_string(),
        };
        let outage = evaluate_nas_observation(&mass_drop_obs, &policy).unwrap();
        assert_eq!(outage.kind, OutageKind::PppoeMassDrop);
        assert_eq!(outage.severity, OutageSeverity::Critical);
        let default_notices = build_whatsapp_notices(&outage, &[]);
        assert_eq!(default_notices.len(), 2);
        assert!(default_notices[0].message.contains("PPPoE massal"));
        assert!(
            default_notices[1]
                .message
                .contains("Mass PPPoE session drop")
        );

        // High latency degradation
        let latency_obs = NasLinkObservation {
            link_up: true,
            latency_ms: Some(420),
            heartbeat_age_secs: 5,
            active_pppoe_sessions: 50,
            dropped_pppoe_sessions: 1,
            ..mass_drop_obs.clone()
        };
        let warn_outage = evaluate_nas_observation(&latency_obs, &policy).unwrap();
        assert_eq!(warn_outage.kind, OutageKind::HighLatencyDegradation);
        assert_eq!(warn_outage.severity, OutageSeverity::Warning);

        // Healthy NAS produces no outage
        let healthy_obs = NasLinkObservation {
            latency_ms: Some(12),
            ..latency_obs
        };
        assert!(evaluate_nas_observation(&healthy_obs, &policy).is_none());
    }
}
