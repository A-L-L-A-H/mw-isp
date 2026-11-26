//! CoA disconnect audit trail and aggregate session metrics.

use serde::Serialize;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DisconnectAuditEntry {
    pub session_row_id: i64,
    pub username: String,
    pub nas_ip: Option<String>,
    pub sent: bool,
    pub ack: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct IspMetrics {
    pub live_sessions: u64,
    pub total_input_octets: i64,
    pub total_output_octets: i64,
    pub disconnects_sent: u64,
    pub disconnects_acked: u64,
    pub disconnects_failed: u64,
}

#[derive(Default)]
pub struct AuditLog {
    entries: Mutex<Vec<DisconnectAuditEntry>>,
}

impl AuditLog {
    pub fn record(&self, entry: DisconnectAuditEntry) {
        self.entries.lock().expect("audit log poisoned").push(entry);
    }

    pub fn entries(&self) -> Vec<DisconnectAuditEntry> {
        self.entries.lock().expect("audit log poisoned").clone()
    }

    pub fn metrics(&self, live_sessions: u64, input_octets: i64, output_octets: i64) -> IspMetrics {
        let entries = self.entries.lock().expect("audit log poisoned");
        IspMetrics {
            live_sessions,
            total_input_octets: input_octets,
            total_output_octets: output_octets,
            disconnects_sent: entries.iter().filter(|e| e.sent).count() as u64,
            disconnects_acked: entries.iter().filter(|e| e.ack).count() as u64,
            disconnects_failed: entries.iter().filter(|e| !e.ack).count() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sent: bool, ack: bool) -> DisconnectAuditEntry {
        DisconnectAuditEntry {
            session_row_id: 1,
            username: "u".into(),
            nas_ip: Some("10.0.0.1".into()),
            sent,
            ack,
            error: None,
        }
    }

    #[test]
    fn metrics_aggregate_audit_outcomes() {
        let log = AuditLog::default();
        log.record(entry(true, true));
        log.record(entry(true, false));
        log.record(entry(false, false));
        let metrics = log.metrics(4, 100, 200);
        assert_eq!(metrics.live_sessions, 4);
        assert_eq!(metrics.disconnects_sent, 2);
        assert_eq!(metrics.disconnects_acked, 1);
        assert_eq!(metrics.disconnects_failed, 2);
        assert_eq!(log.entries().len(), 3);
    }
}
