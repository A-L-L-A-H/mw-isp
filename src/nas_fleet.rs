//! MikroTik NAS fleet management: multi-tower clients, secret rotation, and latency health.

use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::FromRow)]
pub struct NasFleetClient {
    pub id: i64,
    pub name: String,
    pub ip_address: String,
    pub tower_id: Option<String>,
    pub secret: String,
    pub enabled: bool,
    pub latency_ms: Option<i64>,
    pub last_health_check_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NasFleetClientSummary {
    pub id: i64,
    pub name: String,
    pub ip_address: String,
    pub tower_id: Option<String>,
    pub enabled: bool,
    pub latency_ms: Option<i64>,
    pub last_health_check_at: Option<String>,
    pub created_at: String,
}

impl From<NasFleetClient> for NasFleetClientSummary {
    fn from(c: NasFleetClient) -> Self {
        Self {
            id: c.id,
            name: c.name,
            ip_address: c.ip_address,
            tower_id: c.tower_id,
            enabled: c.enabled,
            latency_ms: c.latency_ms,
            last_health_check_at: c.last_health_check_at,
            created_at: c.created_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpsertNasRequest {
    pub name: String,
    pub ip_address: String,
    pub tower_id: Option<String>,
    pub secret: String,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RotateNasSecretRequest {
    pub secret: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateNasHealthRequest {
    pub latency_ms: i64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NasFleetError {
    #[error("secret must be at least 12 characters")]
    SecretTooShort,
    #[error("invalid IP address")]
    InvalidIpAddress,
    #[error("NAS client not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for NasFleetError {
    fn from(err: sqlx::Error) -> Self {
        NasFleetError::Database(err.to_string())
    }
}

#[derive(Clone)]
pub struct NasFleetStore {
    pool: Pool<Sqlite>,
}

impl NasFleetStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    pub async fn list_clients(&self) -> Result<Vec<NasFleetClientSummary>, NasFleetError> {
        let rows = sqlx::query_as::<_, NasFleetClient>(
            "SELECT id, name, ip_address, tower_id, secret, enabled, latency_ms, last_health_check_at, created_at
             FROM nas_clients ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(NasFleetClientSummary::from).collect())
    }

    pub async fn upsert_client(
        &self,
        req: &UpsertNasRequest,
    ) -> Result<NasFleetClientSummary, NasFleetError> {
        if req.secret.len() < 12 {
            return Err(NasFleetError::SecretTooShort);
        }
        if req.ip_address.parse::<std::net::IpAddr>().is_err() {
            return Err(NasFleetError::InvalidIpAddress);
        }

        let enabled = req.enabled.unwrap_or(true);

        let row = sqlx::query_as::<_, NasFleetClient>(
            "INSERT INTO nas_clients (name, ip_address, tower_id, secret, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(ip_address) DO UPDATE SET
               name = excluded.name,
               tower_id = excluded.tower_id,
               secret = excluded.secret,
               enabled = excluded.enabled
             RETURNING id, name, ip_address, tower_id, secret, enabled, latency_ms, last_health_check_at, created_at",
        )
        .bind(&req.name)
        .bind(&req.ip_address)
        .bind(req.tower_id.as_deref())
        .bind(&req.secret)
        .bind(enabled)
        .fetch_one(&self.pool)
        .await?;

        Ok(NasFleetClientSummary::from(row))
    }

    pub async fn delete_client(&self, ip_address: &str) -> Result<bool, NasFleetError> {
        let res = sqlx::query("DELETE FROM nas_clients WHERE ip_address = ?1")
            .bind(ip_address)
            .execute(&self.pool)
            .await?;

        Ok(res.rows_affected() > 0)
    }

    pub async fn rotate_secret(
        &self,
        ip_address: &str,
        new_secret: &str,
        reason: &str,
    ) -> Result<NasFleetClientSummary, NasFleetError> {
        if new_secret.len() < 12 {
            return Err(NasFleetError::SecretTooShort);
        }

        let mut tx = self.pool.begin().await?;

        let client = sqlx::query_as::<_, NasFleetClient>(
            "UPDATE nas_clients SET secret = ?1 WHERE ip_address = ?2
             RETURNING id, name, ip_address, tower_id, secret, enabled, latency_ms, last_health_check_at, created_at",
        )
        .bind(new_secret)
        .bind(ip_address)
        .fetch_optional(&mut *tx)
        .await?;

        let client = match client {
            Some(c) => c,
            None => return Err(NasFleetError::NotFound),
        };

        sqlx::query("INSERT INTO nas_secret_rotations (client_id, reason) VALUES (?1, ?2)")
            .bind(client.id)
            .bind(reason)
            .execute(&mut *tx)
            .await?;

        // Reset active sessions per RFC 2866 §5.4.6
        sqlx::query(
            "UPDATE radius_sessions
             SET status = 'terminated', terminate_cause = 6, stopped_at = datetime('now'), updated_at = datetime('now')
             WHERE nas_ip = ?1 AND status = 'active'",
        )
        .bind(ip_address)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(NasFleetClientSummary::from(client))
    }

    pub async fn update_latency_health(
        &self,
        ip_address: &str,
        latency_ms: i64,
    ) -> Result<NasFleetClientSummary, NasFleetError> {
        let client = sqlx::query_as::<_, NasFleetClient>(
            "UPDATE nas_clients
             SET latency_ms = ?1, last_health_check_at = datetime('now')
             WHERE ip_address = ?2
             RETURNING id, name, ip_address, tower_id, secret, enabled, latency_ms, last_health_check_at, created_at",
        )
        .bind(latency_ms)
        .bind(ip_address)
        .fetch_optional(&self.pool)
        .await?;

        match client {
            Some(c) => Ok(NasFleetClientSummary::from(c)),
            None => Err(NasFleetError::NotFound),
        }
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
            "CREATE TABLE IF NOT EXISTS nas_clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip_address TEXT NOT NULL UNIQUE,
                tower_id TEXT,
                secret TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                latency_ms INTEGER,
                last_health_check_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS nas_secret_rotations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL REFERENCES nas_clients(id) ON DELETE CASCADE,
                rotated_at TEXT NOT NULL DEFAULT (datetime('now')),
                reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS radius_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                nas_ip TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                terminate_cause INTEGER,
                stopped_at TEXT,
                updated_at TEXT
            );",
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    #[tokio::test]
    async fn fleet_crud_rotation_and_health() {
        let pool = setup_test_pool().await;
        let fleet = NasFleetStore::new(pool.clone());

        // 1. Upsert
        let req = UpsertNasRequest {
            name: "Tower-North-1".into(),
            ip_address: "10.100.1.1".into(),
            tower_id: Some("TOWER-NORTH".into()),
            secret: "super-secret-key-123".into(),
            enabled: Some(true),
        };
        let created = fleet.upsert_client(&req).await.unwrap();
        assert_eq!(created.name, "Tower-North-1");
        assert_eq!(created.tower_id.as_deref(), Some("TOWER-NORTH"));

        // 2. List
        let list = fleet.list_clients().await.unwrap();
        assert_eq!(list.len(), 1);

        // 3. Health update
        let health = fleet.update_latency_health("10.100.1.1", 12).await.unwrap();
        assert_eq!(health.latency_ms, Some(12));
        assert!(health.last_health_check_at.is_some());

        // 4. Secret rotation
        let rotated = fleet
            .rotate_secret("10.100.1.1", "new-rotated-secret-456", "scheduled")
            .await
            .unwrap();
        assert_eq!(rotated.ip_address, "10.100.1.1");

        // 5. Delete
        let deleted = fleet.delete_client("10.100.1.1").await.unwrap();
        assert!(deleted);
        assert_eq!(fleet.list_clients().await.unwrap().len(), 0);
    }
}
