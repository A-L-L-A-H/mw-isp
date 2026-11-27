//! CoA disconnect / rate-limit audit trail and aggregate session metrics backed by durable SQLite.

use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::FromRow)]
pub struct DisconnectAuditEntry {
    pub session_row_id: i64,
    pub username: String,
    pub nas_ip: Option<String>,
    #[serde(default = "default_action")]
    pub action: String,
    pub sent: bool,
    pub ack: bool,
    pub error: Option<String>,
}

fn default_action() -> String {
    "disconnect".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IspMetrics {
    pub live_sessions: u64,
    pub total_input_octets: i64,
    pub total_output_octets: i64,
    pub disconnects_sent: u64,
    pub disconnects_acked: u64,
    pub disconnects_failed: u64,
}

#[derive(Clone)]
pub struct AuditLog {
    pool: Pool<Sqlite>,
}

impl AuditLog {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    pub async fn record(&self, entry: &DisconnectAuditEntry) -> Result<(), sqlx::Error> {
        let action = if entry.action.is_empty() {
            "disconnect"
        } else {
            &entry.action
        };
        sqlx::query(
            "INSERT INTO isp_coa_audit (session_row_id, username, nas_ip, action, sent, ack, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(entry.session_row_id)
        .bind(&entry.username)
        .bind(&entry.nas_ip)
        .bind(action)
        .bind(entry.sent)
        .bind(entry.ack)
        .bind(&entry.error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn entries(&self) -> Result<Vec<DisconnectAuditEntry>, sqlx::Error> {
        let rows = sqlx::query_as::<_, DisconnectAuditEntry>(
            "SELECT session_row_id, username, nas_ip, action, sent, ack, error
             FROM isp_coa_audit ORDER BY id DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn metrics(
        &self,
        live_sessions: u64,
        input_octets: i64,
        output_octets: i64,
    ) -> Result<IspMetrics, sqlx::Error> {
        let row: (i64, i64, i64) = sqlx::query_as(
            "SELECT
                COALESCE(SUM(CASE WHEN sent = 1 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN ack = 1 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN ack = 0 THEN 1 ELSE 0 END), 0)
             FROM isp_coa_audit",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(IspMetrics {
            live_sessions,
            total_input_octets: input_octets,
            total_output_octets: output_octets,
            disconnects_sent: row.0 as u64,
            disconnects_acked: row.1 as u64,
            disconnects_failed: row.2 as u64,
        })
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

        sqlx::query("PRAGMA journal_mode = WAL;")
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS isp_coa_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_row_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                nas_ip TEXT,
                action TEXT NOT NULL DEFAULT 'disconnect',
                sent INTEGER NOT NULL DEFAULT 0,
                ack INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    fn entry(sent: bool, ack: bool) -> DisconnectAuditEntry {
        DisconnectAuditEntry {
            session_row_id: 1,
            username: "u".into(),
            nas_ip: Some("10.0.0.1".into()),
            action: "disconnect".into(),
            sent,
            ack,
            error: None,
        }
    }

    #[tokio::test]
    async fn metrics_aggregate_audit_outcomes() {
        let pool = setup_test_pool().await;
        let log = AuditLog::new(pool);
        log.record(&entry(true, true)).await.unwrap();
        log.record(&entry(true, false)).await.unwrap();
        log.record(&entry(false, false)).await.unwrap();
        let metrics = log.metrics(4, 100, 200).await.unwrap();
        assert_eq!(metrics.live_sessions, 4);
        assert_eq!(metrics.disconnects_sent, 2);
        assert_eq!(metrics.disconnects_acked, 1);
        assert_eq!(metrics.disconnects_failed, 2);
        assert_eq!(log.entries().await.unwrap().len(), 3);
    }
}
