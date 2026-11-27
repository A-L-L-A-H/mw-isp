//! Hotspot voucher generation and redemption state tracking backed by durable SQLite.

use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, Deserialize)]
pub struct BatchRequest {
    pub count: u32,
    pub code_length: Option<usize>,
    pub time_limit_secs: u64,
    pub quota_bytes: Option<u64>,
    pub rate_limit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::FromRow)]
pub struct Voucher {
    pub code: String,
    pub time_limit_secs: u64,
    pub quota_bytes: Option<u64>,
    pub mikrotik_rate_limit: String,
    pub redeemed: bool,
    pub redeemed_by: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VoucherError {
    #[error("count must be 1-1000")]
    InvalidCount,
    #[error("time_limit_secs must be > 0")]
    InvalidTimeLimit,
    #[error("rate_limit must look like 2M/5M")]
    InvalidRateLimit,
    #[error("voucher not found")]
    NotFound,
    #[error("voucher already redeemed")]
    AlreadyRedeemed,
    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for VoucherError {
    fn from(err: sqlx::Error) -> Self {
        VoucherError::Database(err.to_string())
    }
}

pub fn valid_rate_limit(value: &str) -> bool {
    let Some((rx, tx)) = value.split_once('/') else {
        return false;
    };
    let ok = |part: &str| {
        let digits = part.trim_end_matches(['k', 'K', 'm', 'M', 'G']);
        !digits.is_empty()
            && part.len() - digits.len() <= 1
            && digits.chars().all(|c| c.is_ascii_digit())
    };
    ok(rx) && ok(tx)
}

#[derive(Clone)]
pub struct VoucherStore {
    pool: Pool<Sqlite>,
}

impl VoucherStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    pub async fn create_batch(&self, req: &BatchRequest) -> Result<Vec<Voucher>, VoucherError> {
        if req.count == 0 || req.count > 1000 {
            return Err(VoucherError::InvalidCount);
        }
        if req.time_limit_secs == 0 {
            return Err(VoucherError::InvalidTimeLimit);
        }
        if !valid_rate_limit(&req.rate_limit) {
            return Err(VoucherError::InvalidRateLimit);
        }

        let length = req.code_length.unwrap_or(10).clamp(8, 32);
        let mut created = Vec::with_capacity(req.count as usize);

        let mut tx = self.pool.begin().await?;

        while created.len() < req.count as usize {
            let code: String = {
                let mut rng = rand::thread_rng();
                (0..length)
                    .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
                    .collect()
            };

            let time_limit = req.time_limit_secs as i64;
            let quota = req.quota_bytes.map(|q| q as i64);

            let res = sqlx::query(
                "INSERT INTO isp_vouchers (code, time_limit_secs, quota_bytes, mikrotik_rate_limit, redeemed, redeemed_by)
                 VALUES (?1, ?2, ?3, ?4, 0, NULL)
                 ON CONFLICT(code) DO NOTHING",
            )
            .bind(&code)
            .bind(time_limit)
            .bind(quota)
            .bind(&req.rate_limit)
            .execute(&mut *tx)
            .await?;

            if res.rows_affected() > 0 {
                created.push(Voucher {
                    code,
                    time_limit_secs: req.time_limit_secs,
                    quota_bytes: req.quota_bytes,
                    mikrotik_rate_limit: req.rate_limit.clone(),
                    redeemed: false,
                    redeemed_by: None,
                });
            }
        }

        tx.commit().await?;
        Ok(created)
    }

    pub async fn redeem(&self, code: &str, username: &str) -> Result<Voucher, VoucherError> {
        let code_upper = code.to_ascii_uppercase();
        let mut tx = self.pool.begin().await?;

        let row: Option<(String, i64, Option<i64>, String, bool, Option<String>)> = sqlx::query_as(
            "SELECT code, time_limit_secs, quota_bytes, mikrotik_rate_limit, redeemed, redeemed_by
             FROM isp_vouchers WHERE code = ?1",
        )
        .bind(&code_upper)
        .fetch_optional(&mut *tx)
        .await?;

        let (c, time_limit, quota, rate_limit, redeemed, _redeemed_by) = match row {
            Some(r) => r,
            None => return Err(VoucherError::NotFound),
        };

        if redeemed {
            return Err(VoucherError::AlreadyRedeemed);
        }

        sqlx::query(
            "UPDATE isp_vouchers
             SET redeemed = 1, redeemed_by = ?1, redeemed_at = datetime('now')
             WHERE code = ?2",
        )
        .bind(username)
        .bind(&code_upper)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(Voucher {
            code: c,
            time_limit_secs: time_limit as u64,
            quota_bytes: quota.map(|q| q as u64),
            mikrotik_rate_limit: rate_limit,
            redeemed: true,
            redeemed_by: Some(username.to_string()),
        })
    }

    pub async fn list(&self) -> Result<Vec<Voucher>, VoucherError> {
        let rows: Vec<(String, i64, Option<i64>, String, bool, Option<String>)> = sqlx::query_as(
            "SELECT code, time_limit_secs, quota_bytes, mikrotik_rate_limit, redeemed, redeemed_by
             FROM isp_vouchers ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(code, time_limit, quota, rate, redeemed, user)| Voucher {
                code,
                time_limit_secs: time_limit as u64,
                quota_bytes: quota.map(|q| q as u64),
                mikrotik_rate_limit: rate,
                redeemed,
                redeemed_by: user,
            })
            .collect())
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
            "CREATE TABLE IF NOT EXISTS isp_vouchers (
                code TEXT PRIMARY KEY,
                time_limit_secs INTEGER NOT NULL,
                quota_bytes INTEGER,
                mikrotik_rate_limit TEXT NOT NULL,
                redeemed INTEGER NOT NULL DEFAULT 0,
                redeemed_by TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                redeemed_at TEXT
            );",
        )
        .execute(&pool)
        .await
        .unwrap();

        pool
    }

    fn request(count: u32) -> BatchRequest {
        BatchRequest {
            count,
            code_length: None,
            time_limit_secs: 3600,
            quota_bytes: Some(1_000_000),
            rate_limit: "2M/5M".into(),
        }
    }

    #[tokio::test]
    async fn batch_generates_unique_codes_with_rate_limit() {
        let pool = setup_test_pool().await;
        let store = VoucherStore::new(pool);
        let batch = store.create_batch(&request(50)).await.unwrap();
        assert_eq!(batch.len(), 50);
        assert_eq!(store.list().await.unwrap().len(), 50);
        assert!(batch.iter().all(|v| v.code.len() == 10 && v.mikrotik_rate_limit == "2M/5M"));
    }

    #[tokio::test]
    async fn redeem_once_only() {
        let pool = setup_test_pool().await;
        let store = VoucherStore::new(pool);
        let code = store.create_batch(&request(1)).await.unwrap()[0].code.clone();
        assert_eq!(
            store.redeem(&code.to_lowercase(), "guest1").await.unwrap().redeemed_by.as_deref(),
            Some("guest1")
        );
        assert_eq!(
            store.redeem(&code, "guest2").await,
            Err(VoucherError::AlreadyRedeemed)
        );
        assert_eq!(store.redeem("NOPE", "g").await, Err(VoucherError::NotFound));
    }

    #[tokio::test]
    async fn validates_input() {
        let pool = setup_test_pool().await;
        let store = VoucherStore::new(pool);
        assert_eq!(store.create_batch(&request(0)).await, Err(VoucherError::InvalidCount));
        let mut bad = request(1);
        bad.rate_limit = "fast".into();
        assert_eq!(store.create_batch(&bad).await, Err(VoucherError::InvalidRateLimit));
        assert!(valid_rate_limit("512k/1M"));
    }
}
