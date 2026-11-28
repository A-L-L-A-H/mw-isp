//! MikroTik PPPoE/NAS link-down detector with 60s hysteresis debounce and
//! localized Bahasa Indonesia WhatsApp outage notifications (V50).
//!
//! Suppresses transient link flaps shorter than 60 seconds, notifies impacted
//! active subscribers at most once per incident, and records suppression,
//! notification, and recovery clear events in `isp_outage_events`.

use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

/// Minimum link-down duration in seconds before an outage notification is sent.
pub const HYSTERESIS_DEBOUNCE_SECS: i64 = 60;

#[derive(Debug, Clone, Deserialize)]
pub struct LinkObservationRequest {
    pub nas_ip: String,
    pub tower_id: Option<String>,
    pub link_up: bool,
    pub observed_at_epoch_secs: i64,
    #[serde(default)]
    pub impacted_subscribers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::FromRow)]
pub struct OutageEventRecord {
    pub id: i64,
    pub incident_id: String,
    pub nas_ip: String,
    pub tower_id: Option<String>,
    pub event_type: String,
    pub suppressed: bool,
    pub notified_subscribers: i64,
    pub message_id_locale: String,
    pub observed_at_epoch_secs: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkObservationResult {
    pub incident_id: String,
    pub event_type: String,
    pub suppressed: bool,
    pub notified_subscribers: usize,
    pub whatsapp_message_id: String,
    pub recipients: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OutageNotifierError {
    #[error("nas_ip must not be empty")]
    InvalidNasIp,
    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for OutageNotifierError {
    fn from(err: sqlx::Error) -> Self {
        OutageNotifierError::Database(err.to_string())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct NasOutageStateRow {
    #[allow(dead_code)]
    nas_ip: String,
    tower_id: Option<String>,
    down_since_epoch_secs: Option<i64>,
    incident_id: Option<String>,
    notified: bool,
}

#[derive(Clone)]
pub struct OutageNotifier {
    pool: Pool<Sqlite>,
}

impl OutageNotifier {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    /// Observe a NAS / PPPoE link state sample and apply 60-second hysteresis
    /// debouncing before emitting a single localized Bahasa Indonesia outage notice
    /// per incident, plus a recovery clear message when the link returns.
    pub async fn observe_link(
        &self,
        req: &LinkObservationRequest,
    ) -> Result<LinkObservationResult, OutageNotifierError> {
        let nas_ip = req.nas_ip.trim();
        if nas_ip.is_empty() {
            return Err(OutageNotifierError::InvalidNasIp);
        }

        let state = self.get_state(nas_ip).await?;
        let tower_label = req
            .tower_id
            .as_deref()
            .or_else(|| state.as_ref().and_then(|s| s.tower_id.as_deref()))
            .unwrap_or(nas_ip)
            .to_string();

        if !req.link_up {
            self.handle_link_down(nas_ip, &tower_label, req, state)
                .await
        } else {
            self.handle_link_up(nas_ip, &tower_label, req, state).await
        }
    }

    pub async fn list_events(
        &self,
        nas_ip: Option<&str>,
    ) -> Result<Vec<OutageEventRecord>, OutageNotifierError> {
        let rows: Vec<OutageEventRecord> = match nas_ip {
            Some(ip) => {
                sqlx::query_as(
                    "SELECT id, incident_id, nas_ip, tower_id, event_type,
                            suppressed, notified_subscribers, message_id_locale,
                            observed_at_epoch_secs, created_at
                     FROM isp_outage_events
                     WHERE nas_ip = ?1
                     ORDER BY id ASC",
                )
                .bind(ip)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT id, incident_id, nas_ip, tower_id, event_type,
                            suppressed, notified_subscribers, message_id_locale,
                            observed_at_epoch_secs, created_at
                     FROM isp_outage_events
                     ORDER BY id ASC",
                )
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(rows)
    }

    async fn handle_link_down(
        &self,
        nas_ip: &str,
        tower_label: &str,
        req: &LinkObservationRequest,
        state: Option<NasOutageStateRow>,
    ) -> Result<LinkObservationResult, OutageNotifierError> {
        let (down_since, incident_id, already_notified) = match state {
            Some(s) if s.down_since_epoch_secs.is_some() => (
                s.down_since_epoch_secs.unwrap(),
                s.incident_id
                    .unwrap_or_else(|| format!("INC-{nas_ip}-{}", req.observed_at_epoch_secs)),
                s.notified,
            ),
            _ => (
                req.observed_at_epoch_secs,
                format!("INC-{nas_ip}-{}", req.observed_at_epoch_secs),
                false,
            ),
        };

        let elapsed = (req.observed_at_epoch_secs - down_since).max(0);

        if elapsed < HYSTERESIS_DEBOUNCE_SECS {
            self.upsert_state(
                nas_ip,
                req.tower_id.as_deref(),
                Some(down_since),
                Some(&incident_id),
                false,
            )
            .await?;
            let msg = format!(
                "[DITAHAN HYSTERESIS {elapsed}s < {HYSTERESIS_DEBOUNCE_SECS}s] Flapping link PPPoE/NAS pada {tower_label} ({nas_ip}) belum melewati ambang 60 detik."
            );
            self.insert_event(
                &incident_id,
                nas_ip,
                req.tower_id.as_deref(),
                "flap_suppressed",
                true,
                0,
                &msg,
                req.observed_at_epoch_secs,
            )
            .await?;

            return Ok(LinkObservationResult {
                incident_id,
                event_type: "flap_suppressed".to_string(),
                suppressed: true,
                notified_subscribers: 0,
                whatsapp_message_id: msg,
                recipients: Vec::new(),
            });
        }

        if already_notified {
            let msg = format!(
                "[DUPLIKAT DITAHAN] Notifikasi gangguan untuk insiden {incident_id} pada {tower_label} ({nas_ip}) sudah dikirim sebelumnya."
            );
            self.insert_event(
                &incident_id,
                nas_ip,
                req.tower_id.as_deref(),
                "duplicate_suppressed",
                true,
                0,
                &msg,
                req.observed_at_epoch_secs,
            )
            .await?;

            return Ok(LinkObservationResult {
                incident_id,
                event_type: "duplicate_suppressed".to_string(),
                suppressed: true,
                notified_subscribers: 0,
                whatsapp_message_id: msg,
                recipients: Vec::new(),
            });
        }

        // Hysteresis window elapsed and not yet notified: resolve active subscribers.
        let recipients = self
            .resolve_impacted_subscribers(nas_ip, &req.impacted_subscribers)
            .await?;
        let count = recipients.len();
        let msg = format!(
            "[INFO GANGGUAN JARINGAN] Pelanggan Yth, terdeteksi gangguan link PPPoE/NAS pada titik {tower_label} ({nas_ip}) selama {elapsed} detik. Tim teknis MoonWitness ISP sedang melakukan penanganan. Mohon maaf atas ketidaknyamanan Anda."
        );

        self.upsert_state(
            nas_ip,
            req.tower_id.as_deref(),
            Some(down_since),
            Some(&incident_id),
            true,
        )
        .await?;
        self.insert_event(
            &incident_id,
            nas_ip,
            req.tower_id.as_deref(),
            "outage_notified",
            false,
            count as i64,
            &msg,
            req.observed_at_epoch_secs,
        )
        .await?;

        Ok(LinkObservationResult {
            incident_id,
            event_type: "outage_notified".to_string(),
            suppressed: false,
            notified_subscribers: count,
            whatsapp_message_id: msg,
            recipients,
        })
    }

    async fn handle_link_up(
        &self,
        nas_ip: &str,
        tower_label: &str,
        req: &LinkObservationRequest,
        state: Option<NasOutageStateRow>,
    ) -> Result<LinkObservationResult, OutageNotifierError> {
        let Some(s) = state.filter(|s| s.down_since_epoch_secs.is_some()) else {
            let incident_id = format!("HEALTHY-{nas_ip}");
            return Ok(LinkObservationResult {
                incident_id,
                event_type: "healthy_noop".to_string(),
                suppressed: true,
                notified_subscribers: 0,
                whatsapp_message_id: format!("Link {tower_label} ({nas_ip}) normal."),
                recipients: Vec::new(),
            });
        };

        let incident_id = s
            .incident_id
            .unwrap_or_else(|| format!("INC-{nas_ip}-{}", req.observed_at_epoch_secs));

        // Reset down state.
        self.upsert_state(nas_ip, req.tower_id.as_deref(), None, None, false)
            .await?;

        if !s.notified {
            let msg = format!(
                "[PULIH SEBELUM 60 DETIK] Link PPPoE/NAS pada {tower_label} ({nas_ip}) pulih sebelum ambang hysteresis; tidak ada pesan WA yang dikirim."
            );
            self.insert_event(
                &incident_id,
                nas_ip,
                req.tower_id.as_deref(),
                "flap_recovered_suppressed",
                true,
                0,
                &msg,
                req.observed_at_epoch_secs,
            )
            .await?;

            return Ok(LinkObservationResult {
                incident_id,
                event_type: "flap_recovered_suppressed".to_string(),
                suppressed: true,
                notified_subscribers: 0,
                whatsapp_message_id: msg,
                recipients: Vec::new(),
            });
        }

        let recipients = self
            .resolve_impacted_subscribers(nas_ip, &req.impacted_subscribers)
            .await?;
        let count = recipients.len();
        let msg = format!(
            "[LAYANAN PULIH] Alhamdulillah, koneksi jaringan PPPoE/NAS pada titik {tower_label} ({nas_ip}) untuk insiden {incident_id} telah pulih dan normal kembali. Terima kasih atas kesabaran Anda."
        );

        self.insert_event(
            &incident_id,
            nas_ip,
            req.tower_id.as_deref(),
            "recovery_clear",
            false,
            count as i64,
            &msg,
            req.observed_at_epoch_secs,
        )
        .await?;

        Ok(LinkObservationResult {
            incident_id,
            event_type: "recovery_clear".to_string(),
            suppressed: false,
            notified_subscribers: count,
            whatsapp_message_id: msg,
            recipients,
        })
    }

    async fn resolve_impacted_subscribers(
        &self,
        nas_ip: &str,
        explicit: &[String],
    ) -> Result<Vec<String>, sqlx::Error> {
        if !explicit.is_empty() {
            let mut deduped = explicit.to_vec();
            deduped.sort();
            deduped.dedup();
            return Ok(deduped);
        }
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT username FROM radius_sessions WHERE nas_ip = ?1 AND status = 'active' ORDER BY username ASC",
        )
        .bind(nas_ip)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(u,)| u).collect())
    }

    async fn get_state(&self, nas_ip: &str) -> Result<Option<NasOutageStateRow>, sqlx::Error> {
        sqlx::query_as(
            "SELECT nas_ip, tower_id, down_since_epoch_secs, incident_id, notified
             FROM isp_nas_outage_state
             WHERE nas_ip = ?1",
        )
        .bind(nas_ip)
        .fetch_optional(&self.pool)
        .await
    }

    async fn upsert_state(
        &self,
        nas_ip: &str,
        tower_id: Option<&str>,
        down_since: Option<i64>,
        incident_id: Option<&str>,
        notified: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO isp_nas_outage_state (nas_ip, tower_id, down_since_epoch_secs, incident_id, notified, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
             ON CONFLICT(nas_ip) DO UPDATE SET
               tower_id = COALESCE(excluded.tower_id, isp_nas_outage_state.tower_id),
               down_since_epoch_secs = excluded.down_since_epoch_secs,
               incident_id = excluded.incident_id,
               notified = excluded.notified,
               updated_at = datetime('now')",
        )
        .bind(nas_ip)
        .bind(tower_id)
        .bind(down_since)
        .bind(incident_id)
        .bind(notified)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_event(
        &self,
        incident_id: &str,
        nas_ip: &str,
        tower_id: Option<&str>,
        event_type: &str,
        suppressed: bool,
        notified_subscribers: i64,
        message_id_locale: &str,
        observed_at_epoch_secs: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO isp_outage_events (
                incident_id, nas_ip, tower_id, event_type, suppressed,
                notified_subscribers, message_id_locale, observed_at_epoch_secs
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(incident_id)
        .bind(nas_ip)
        .bind(tower_id)
        .bind(event_type)
        .bind(suppressed)
        .bind(notified_subscribers)
        .bind(message_id_locale)
        .bind(observed_at_epoch_secs)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup_test_pool() -> Pool<Sqlite> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn debounces_transient_flaps_and_notifies_once_then_clears_on_recovery() {
        let pool = setup_test_pool().await;
        let notifier = OutageNotifier::new(pool);

        // 1. Link goes down at t=1000 -> suppressed (0s < 60s hysteresis)
        let first = notifier
            .observe_link(&LinkObservationRequest {
                nas_ip: "10.10.0.1".to_string(),
                tower_id: Some("TOWER-DEPOK-01".to_string()),
                link_up: false,
                observed_at_epoch_secs: 1000,
                impacted_subscribers: vec!["sub01@isp".to_string(), "sub02@isp".to_string()],
            })
            .await
            .unwrap();
        assert!(first.suppressed);
        assert_eq!(first.event_type, "flap_suppressed");
        assert_eq!(first.notified_subscribers, 0);

        // 2. Link recovers at t=1030 (30s < 60s) -> transient flap cleared without notification
        let recovered_early = notifier
            .observe_link(&LinkObservationRequest {
                nas_ip: "10.10.0.1".to_string(),
                tower_id: Some("TOWER-DEPOK-01".to_string()),
                link_up: true,
                observed_at_epoch_secs: 1030,
                impacted_subscribers: vec!["sub01@isp".to_string(), "sub02@isp".to_string()],
            })
            .await
            .unwrap();
        assert!(recovered_early.suppressed);
        assert_eq!(recovered_early.event_type, "flap_recovered_suppressed");

        // 3. New outage starts at t=2000 -> suppressed initially
        let down_start = notifier
            .observe_link(&LinkObservationRequest {
                nas_ip: "10.10.0.1".to_string(),
                tower_id: Some("TOWER-DEPOK-01".to_string()),
                link_up: false,
                observed_at_epoch_secs: 2000,
                impacted_subscribers: vec!["sub01@isp".to_string(), "sub02@isp".to_string()],
            })
            .await
            .unwrap();
        assert!(down_start.suppressed);

        // 4. Still down at t=2065 (65s >= 60s) -> notifies impacted subscribers once
        let notified = notifier
            .observe_link(&LinkObservationRequest {
                nas_ip: "10.10.0.1".to_string(),
                tower_id: Some("TOWER-DEPOK-01".to_string()),
                link_up: false,
                observed_at_epoch_secs: 2065,
                impacted_subscribers: vec!["sub01@isp".to_string(), "sub02@isp".to_string()],
            })
            .await
            .unwrap();
        assert!(!notified.suppressed);
        assert_eq!(notified.event_type, "outage_notified");
        assert_eq!(notified.notified_subscribers, 2);
        assert!(
            notified
                .whatsapp_message_id
                .contains("INFO GANGGUAN JARINGAN")
        );

        // 5. Still down at t=2120 -> duplicate notification suppressed
        let duplicate = notifier
            .observe_link(&LinkObservationRequest {
                nas_ip: "10.10.0.1".to_string(),
                tower_id: Some("TOWER-DEPOK-01".to_string()),
                link_up: false,
                observed_at_epoch_secs: 2120,
                impacted_subscribers: vec!["sub01@isp".to_string(), "sub02@isp".to_string()],
            })
            .await
            .unwrap();
        assert!(duplicate.suppressed);
        assert_eq!(duplicate.event_type, "duplicate_suppressed");

        // 6. Link recovers at t=2200 -> sends localized recovery clear message
        let clear = notifier
            .observe_link(&LinkObservationRequest {
                nas_ip: "10.10.0.1".to_string(),
                tower_id: Some("TOWER-DEPOK-01".to_string()),
                link_up: true,
                observed_at_epoch_secs: 2200,
                impacted_subscribers: vec!["sub01@isp".to_string(), "sub02@isp".to_string()],
            })
            .await
            .unwrap();
        assert!(!clear.suppressed);
        assert_eq!(clear.event_type, "recovery_clear");
        assert!(clear.whatsapp_message_id.contains("LAYANAN PULIH"));

        let events = notifier.list_events(Some("10.10.0.1")).await.unwrap();
        assert_eq!(events.len(), 6);
    }
}
