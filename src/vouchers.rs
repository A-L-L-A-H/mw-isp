//! Hotspot voucher generation, prepaid checkout, QRIS settlement hook,
//! instant RADIUS batch activation, and durable SQLite state tracking.

use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{Pool, Sqlite};

const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(default = "default_voucher_status")]
    pub status: String,
}

fn default_voucher_status() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotCheckoutRequest {
    pub order_id: Option<String>,
    pub customer_phone: Option<String>,
    pub package_code: String,
    pub count: u32,
    pub amount_idr: i64,
    pub time_limit_secs: u64,
    pub quota_bytes: Option<u64>,
    pub rate_limit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HotspotOrder {
    pub order_id: String,
    pub customer_phone: Option<String>,
    pub package_code: String,
    pub voucher_count: u32,
    pub amount_idr: i64,
    pub time_limit_secs: u64,
    pub quota_bytes: Option<u64>,
    pub mikrotik_rate_limit: String,
    pub qris_reference: String,
    pub qris_payload: String,
    pub status: String,
    pub settled_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrisSettlementPayload {
    pub order_id: Option<String>,
    pub qris_reference: Option<String>,
    pub paid_amount_idr: i64,
    pub settlement_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QrisSettlementResult {
    pub order: HotspotOrder,
    pub vouchers: Vec<Voucher>,
    pub radius_activated_count: usize,
    pub idempotent_replay: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VoucherError {
    #[error("count must be 1-1000")]
    InvalidCount,
    #[error("time_limit_secs must be > 0")]
    InvalidTimeLimit,
    #[error("rate_limit must look like 2M/5M")]
    InvalidRateLimit,
    #[error("amount_idr must be > 0")]
    InvalidAmount,
    #[error("package_code is required")]
    InvalidPackage,
    #[error("voucher not found")]
    NotFound,
    #[error("voucher order not found")]
    OrderNotFound,
    #[error("voucher order is not pending (current status: {0})")]
    OrderNotPending(String),
    #[error("QRIS settlement amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch { expected: i64, actual: i64 },
    #[error("unsupported QRIS settlement status: {0}")]
    InvalidSettlementStatus(String),
    #[error("invalid QRIS webhook signature")]
    InvalidSignature,
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
    parse_rate_limit_kbps(value).is_some()
}

/// Parses a RouterOS `rx/tx` rate limit string (e.g. `"2M/5M"` or `"512k/1M"`)
/// into `(upload_kbps, download_kbps)`.
pub fn parse_rate_limit_kbps(value: &str) -> Option<(i64, i64)> {
    let (rx, tx) = value.split_once('/')?;
    let parse_part = |part: &str| -> Option<i64> {
        if part.is_empty() {
            return None;
        }
        let digits = part.trim_end_matches(['k', 'K', 'm', 'M', 'G']);
        if digits.is_empty()
            || part.len() - digits.len() > 1
            || !digits.chars().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        let base: i64 = digits.parse().ok()?;
        if base <= 0 {
            return None;
        }
        let suffix = &part[digits.len()..];
        let kbps = match suffix {
            "" | "k" | "K" => base,
            "m" | "M" => base.checked_mul(1_000)?,
            "G" => base.checked_mul(1_000_000)?,
            _ => return None,
        };
        Some(kbps)
    };
    Some((parse_part(rx)?, parse_part(tx)?))
}

/// Verifies an HMAC-SHA256 hex signature over a raw QRIS webhook payload in constant time.
pub fn verify_qris_signature(secret: &str, payload: &[u8], signature_hex: &str) -> bool {
    let secret_trimmed = secret.trim();
    let sig_trimmed = signature_hex
        .trim()
        .strip_prefix("sha256=")
        .unwrap_or_else(|| signature_hex.trim());
    if secret_trimmed.is_empty() || sig_trimmed.is_empty() {
        return false;
    }
    let Ok(presented) = hex::decode(sig_trimmed) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret_trimmed.as_bytes()) else {
        return false;
    };
    mac.update(payload);
    mac.verify_slice(&presented).is_ok()
}

fn generate_code(length: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
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
        let Some((upload_kbps, download_kbps)) = parse_rate_limit_kbps(&req.rate_limit) else {
            return Err(VoucherError::InvalidRateLimit);
        };

        let length = req.code_length.unwrap_or(10).clamp(8, 32);
        let mut created = Vec::with_capacity(req.count as usize);

        let mut tx = self.pool.begin().await?;

        while created.len() < req.count as usize {
            let code = generate_code(length);
            let time_limit = req.time_limit_secs as i64;
            let quota = req.quota_bytes.map(|q| q as i64);

            let res = sqlx::query(
                "INSERT INTO isp_vouchers (code, time_limit_secs, quota_bytes, mikrotik_rate_limit, redeemed, redeemed_by, order_id, status)
                 VALUES (?1, ?2, ?3, ?4, 0, NULL, NULL, 'active')
                 ON CONFLICT(code) DO NOTHING",
            )
            .bind(&code)
            .bind(time_limit)
            .bind(quota)
            .bind(&req.rate_limit)
            .execute(&mut *tx)
            .await?;

            if res.rows_affected() > 0 {
                let _ = sqlx::query(
                    "INSERT INTO subscribers (username, password, connection_type, download_kbps, upload_kbps, status, quota_bytes)
                     VALUES (?1, ?2, 'hotspot', ?3, ?4, 'active', ?5)
                     ON CONFLICT(username) DO UPDATE SET
                       password = excluded.password,
                       connection_type = 'hotspot',
                       download_kbps = excluded.download_kbps,
                       upload_kbps = excluded.upload_kbps,
                       status = 'active',
                       quota_bytes = excluded.quota_bytes",
                )
                .bind(&code)
                .bind(&code)
                .bind(download_kbps)
                .bind(upload_kbps)
                .bind(quota.unwrap_or(0))
                .execute(&mut *tx)
                .await;

                created.push(Voucher {
                    code,
                    time_limit_secs: req.time_limit_secs,
                    quota_bytes: req.quota_bytes,
                    mikrotik_rate_limit: req.rate_limit.clone(),
                    redeemed: false,
                    redeemed_by: None,
                    order_id: None,
                    status: "active".to_string(),
                });
            }
        }

        tx.commit().await?;
        Ok(created)
    }

    /// Create a durable pending prepaid Hotspot voucher checkout order with QRIS payment payload.
    pub async fn checkout(
        &self,
        req: &HotspotCheckoutRequest,
    ) -> Result<HotspotOrder, VoucherError> {
        if req.count == 0 || req.count > 1000 {
            return Err(VoucherError::InvalidCount);
        }
        if req.time_limit_secs == 0 {
            return Err(VoucherError::InvalidTimeLimit);
        }
        if !valid_rate_limit(&req.rate_limit) {
            return Err(VoucherError::InvalidRateLimit);
        }
        if req.amount_idr <= 0 {
            return Err(VoucherError::InvalidAmount);
        }
        let pkg = req.package_code.trim();
        if pkg.is_empty() {
            return Err(VoucherError::InvalidPackage);
        }

        let order_id = req
            .order_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("ORD-{}", generate_code(12)));

        let qris_reference = format!("QRIS-{order_id}");
        let qris_payload = format!(
            "00020101021226580014ID.CO.QRIS.WWW0118936009153000000000520448145303360540{len:02}{amt}5802ID5915MOONWITNESS ISP6007JAKARTA62180114{order_id}6304ABCD",
            len = req.amount_idr.to_string().len(),
            amt = req.amount_idr
        );

        let time_limit = req.time_limit_secs as i64;
        let quota = req.quota_bytes.map(|q| q as i64);

        sqlx::query(
            "INSERT INTO hotspot_voucher_orders (
                order_id, customer_phone, package_code, voucher_count, amount_idr,
                time_limit_secs, quota_bytes, mikrotik_rate_limit, qris_reference, qris_payload, status
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending')",
        )
        .bind(&order_id)
        .bind(req.customer_phone.as_deref())
        .bind(pkg)
        .bind(req.count as i64)
        .bind(req.amount_idr)
        .bind(time_limit)
        .bind(quota)
        .bind(&req.rate_limit)
        .bind(&qris_reference)
        .bind(&qris_payload)
        .execute(&self.pool)
        .await?;

        Ok(HotspotOrder {
            order_id,
            customer_phone: req.customer_phone.clone(),
            package_code: pkg.to_string(),
            voucher_count: req.count,
            amount_idr: req.amount_idr,
            time_limit_secs: req.time_limit_secs,
            quota_bytes: req.quota_bytes,
            mikrotik_rate_limit: req.rate_limit.clone(),
            qris_reference,
            qris_payload,
            status: "pending".to_string(),
            settled_at: None,
        })
    }

    /// Process a QRIS settlement callback: atomically settles the order, mints the durable voucher
    /// batch, and provisions each voucher as an active hotspot RADIUS subscriber.
    #[allow(clippy::type_complexity)]
    pub async fn settle_qris(
        &self,
        payload: &QrisSettlementPayload,
    ) -> Result<QrisSettlementResult, VoucherError> {
        let mut tx = self.pool.begin().await?;

        let order_row: Option<(
            String,
            Option<String>,
            String,
            i64,
            i64,
            i64,
            Option<i64>,
            String,
            String,
            String,
            String,
            Option<String>,
        )> = if let Some(order_id) = payload
            .order_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            sqlx::query_as(
                "SELECT order_id, customer_phone, package_code, voucher_count, amount_idr,
                        time_limit_secs, quota_bytes, mikrotik_rate_limit, qris_reference,
                        qris_payload, status, settled_at
                 FROM hotspot_voucher_orders WHERE order_id = ?1",
            )
            .bind(order_id)
            .fetch_optional(&mut *tx)
            .await?
        } else if let Some(qris_ref) = payload
            .qris_reference
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            sqlx::query_as(
                "SELECT order_id, customer_phone, package_code, voucher_count, amount_idr,
                        time_limit_secs, quota_bytes, mikrotik_rate_limit, qris_reference,
                        qris_payload, status, settled_at
                 FROM hotspot_voucher_orders WHERE qris_reference = ?1",
            )
            .bind(qris_ref)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            None
        };

        let Some((
            order_id,
            customer_phone,
            package_code,
            voucher_count,
            amount_idr,
            time_limit_secs,
            quota_bytes,
            mikrotik_rate_limit,
            qris_reference,
            qris_payload,
            status,
            settled_at,
        )) = order_row
        else {
            return Err(VoucherError::OrderNotFound);
        };

        let mut order = HotspotOrder {
            order_id: order_id.clone(),
            customer_phone,
            package_code,
            voucher_count: voucher_count as u32,
            amount_idr,
            time_limit_secs: time_limit_secs as u64,
            quota_bytes: quota_bytes.map(|q| q as u64),
            mikrotik_rate_limit: mikrotik_rate_limit.clone(),
            qris_reference,
            qris_payload,
            status: status.clone(),
            settled_at,
        };

        // Idempotent replay: if already settled, return the existing activated vouchers.
        if status == "settled" {
            let existing_rows: Vec<(
                String,
                i64,
                Option<i64>,
                String,
                bool,
                Option<String>,
                Option<String>,
                String,
            )> = sqlx::query_as(
                "SELECT code, time_limit_secs, quota_bytes, mikrotik_rate_limit, redeemed, redeemed_by, order_id, status
                 FROM isp_vouchers WHERE order_id = ?1 ORDER BY code ASC",
            )
            .bind(&order_id)
            .fetch_all(&mut *tx)
            .await?;

            let vouchers: Vec<Voucher> = existing_rows
                .into_iter()
                .map(|(code, tl, qb, rl, red, rb, oid, st)| Voucher {
                    code,
                    time_limit_secs: tl as u64,
                    quota_bytes: qb.map(|q| q as u64),
                    mikrotik_rate_limit: rl,
                    redeemed: red,
                    redeemed_by: rb,
                    order_id: oid,
                    status: st,
                })
                .collect();
            let count = vouchers.len();
            tx.commit().await?;
            return Ok(QrisSettlementResult {
                order,
                vouchers,
                radius_activated_count: count,
                idempotent_replay: true,
            });
        }

        if status != "pending" {
            return Err(VoucherError::OrderNotPending(status));
        }

        if payload.paid_amount_idr != amount_idr {
            return Err(VoucherError::AmountMismatch {
                expected: amount_idr,
                actual: payload.paid_amount_idr,
            });
        }

        let norm_status = payload.settlement_status.trim().to_ascii_uppercase();
        match norm_status.as_str() {
            "FAILED" | "EXPIRED" | "CANCELLED" => {
                let target_status = norm_status.to_ascii_lowercase();
                sqlx::query("UPDATE hotspot_voucher_orders SET status = ?1 WHERE order_id = ?2")
                    .bind(&target_status)
                    .bind(&order_id)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                order.status = target_status;
                return Ok(QrisSettlementResult {
                    order,
                    vouchers: Vec::new(),
                    radius_activated_count: 0,
                    idempotent_replay: false,
                });
            }
            "PAID" | "SETTLED" | "SUCCESS" => {}
            other => return Err(VoucherError::InvalidSettlementStatus(other.to_string())),
        }

        let (upload_kbps, download_kbps) =
            parse_rate_limit_kbps(&mikrotik_rate_limit).ok_or(VoucherError::InvalidRateLimit)?;

        sqlx::query(
            "UPDATE hotspot_voucher_orders
             SET status = 'settled', settled_at = datetime('now')
             WHERE order_id = ?1",
        )
        .bind(&order_id)
        .execute(&mut *tx)
        .await?;

        let settled_ts: Option<String> =
            sqlx::query_scalar("SELECT settled_at FROM hotspot_voucher_orders WHERE order_id = ?1")
                .bind(&order_id)
                .fetch_one(&mut *tx)
                .await?;

        order.status = "settled".to_string();
        order.settled_at = settled_ts;

        let mut vouchers = Vec::with_capacity(order.voucher_count as usize);
        while vouchers.len() < order.voucher_count as usize {
            let code = generate_code(10);
            let res = sqlx::query(
                "INSERT INTO isp_vouchers (
                    code, time_limit_secs, quota_bytes, mikrotik_rate_limit,
                    redeemed, redeemed_by, order_id, status
                 ) VALUES (?1, ?2, ?3, ?4, 0, NULL, ?5, 'active')
                 ON CONFLICT(code) DO NOTHING",
            )
            .bind(&code)
            .bind(time_limit_secs)
            .bind(quota_bytes)
            .bind(&mikrotik_rate_limit)
            .bind(&order_id)
            .execute(&mut *tx)
            .await?;

            if res.rows_affected() > 0 {
                // Instant RADIUS batch activation: insert active hotspot subscriber row.
                let _ = sqlx::query(
                    "INSERT INTO subscribers (
                        username, password, connection_type, download_kbps, upload_kbps, status, quota_bytes
                     ) VALUES (?1, ?2, 'hotspot', ?3, ?4, 'active', ?5)
                     ON CONFLICT(username) DO UPDATE SET
                       password = excluded.password,
                       connection_type = 'hotspot',
                       download_kbps = excluded.download_kbps,
                       upload_kbps = excluded.upload_kbps,
                       status = 'active',
                       quota_bytes = excluded.quota_bytes",
                )
                .bind(&code)
                .bind(&code)
                .bind(download_kbps)
                .bind(upload_kbps)
                .bind(quota_bytes.unwrap_or(0))
                .execute(&mut *tx)
                .await;

                vouchers.push(Voucher {
                    code,
                    time_limit_secs: order.time_limit_secs,
                    quota_bytes: order.quota_bytes,
                    mikrotik_rate_limit: mikrotik_rate_limit.clone(),
                    redeemed: false,
                    redeemed_by: None,
                    order_id: Some(order_id.clone()),
                    status: "active".to_string(),
                });
            }
        }

        tx.commit().await?;
        let activated = vouchers.len();
        Ok(QrisSettlementResult {
            order,
            vouchers,
            radius_activated_count: activated,
            idempotent_replay: false,
        })
    }

    #[allow(clippy::type_complexity)]
    pub async fn redeem(&self, code: &str, username: &str) -> Result<Voucher, VoucherError> {
        let code_upper = code.to_ascii_uppercase();
        let mut tx = self.pool.begin().await?;

        let row: Option<(
            String,
            i64,
            Option<i64>,
            String,
            bool,
            Option<String>,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT code, time_limit_secs, quota_bytes, mikrotik_rate_limit, redeemed, redeemed_by, order_id, status
             FROM isp_vouchers WHERE code = ?1",
        )
        .bind(&code_upper)
        .fetch_optional(&mut *tx)
        .await?;

        let (c, time_limit, quota, rate_limit, redeemed, _redeemed_by, order_id, _status) =
            match row {
                Some(r) => r,
                None => return Err(VoucherError::NotFound),
            };

        if redeemed {
            return Err(VoucherError::AlreadyRedeemed);
        }

        sqlx::query(
            "UPDATE isp_vouchers
             SET redeemed = 1, redeemed_by = ?1, redeemed_at = datetime('now'), status = 'redeemed'
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
            order_id,
            status: "redeemed".to_string(),
        })
    }

    #[allow(clippy::type_complexity)]
    pub async fn list(&self) -> Result<Vec<Voucher>, VoucherError> {
        let rows: Vec<(
            String,
            i64,
            Option<i64>,
            String,
            bool,
            Option<String>,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT code, time_limit_secs, quota_bytes, mikrotik_rate_limit, redeemed, redeemed_by, order_id, status
             FROM isp_vouchers ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(code, time_limit, quota, rate, redeemed, user, order_id, status)| Voucher {
                    code,
                    time_limit_secs: time_limit as u64,
                    quota_bytes: quota.map(|q| q as u64),
                    mikrotik_rate_limit: rate,
                    redeemed,
                    redeemed_by: user,
                    order_id,
                    status,
                },
            )
            .collect())
    }

    /// Prune redeemed vouchers whose `time_limit_secs` window has elapsed since `redeemed_at`.
    pub async fn prune_expired(&self) -> Result<u64, VoucherError> {
        let res = sqlx::query(
            "DELETE FROM isp_vouchers
             WHERE redeemed = 1
               AND redeemed_at IS NOT NULL
               AND (strftime('%s', 'now') - strftime('%s', redeemed_at)) >= time_limit_secs",
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
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
            "CREATE TABLE IF NOT EXISTS subscribers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                connection_type TEXT NOT NULL DEFAULT 'pppoe',
                framed_ip TEXT,
                download_kbps INTEGER NOT NULL DEFAULT 20480,
                upload_kbps INTEGER NOT NULL DEFAULT 10240,
                status TEXT NOT NULL DEFAULT 'active',
                quota_bytes INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS isp_vouchers (
                code TEXT PRIMARY KEY,
                time_limit_secs INTEGER NOT NULL,
                quota_bytes INTEGER,
                mikrotik_rate_limit TEXT NOT NULL,
                redeemed INTEGER NOT NULL DEFAULT 0,
                redeemed_by TEXT,
                order_id TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                redeemed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS hotspot_voucher_orders (
                order_id TEXT PRIMARY KEY,
                customer_phone TEXT,
                package_code TEXT NOT NULL,
                voucher_count INTEGER NOT NULL,
                amount_idr INTEGER NOT NULL,
                time_limit_secs INTEGER NOT NULL,
                quota_bytes INTEGER,
                mikrotik_rate_limit TEXT NOT NULL,
                qris_reference TEXT NOT NULL UNIQUE,
                qris_payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                settled_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
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
        assert!(batch.iter().all(|v| v.code.len() == 10
            && v.mikrotik_rate_limit == "2M/5M"
            && v.status == "active"));
    }

    #[tokio::test]
    async fn redeem_once_only() {
        let pool = setup_test_pool().await;
        let store = VoucherStore::new(pool);
        let code = store.create_batch(&request(1)).await.unwrap()[0]
            .code
            .clone();
        let redeemed = store.redeem(&code.to_lowercase(), "guest1").await.unwrap();
        assert_eq!(redeemed.redeemed_by.as_deref(), Some("guest1"));
        assert_eq!(redeemed.status, "redeemed");
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
        assert_eq!(
            store.create_batch(&request(0)).await,
            Err(VoucherError::InvalidCount)
        );
        let mut bad = request(1);
        bad.rate_limit = "fast".into();
        assert_eq!(
            store.create_batch(&bad).await,
            Err(VoucherError::InvalidRateLimit)
        );
        assert!(valid_rate_limit("512k/1M"));
    }

    #[tokio::test]
    async fn hotspot_checkout_to_qris_settlement_activates_radius_batch_durably() {
        let pool = setup_test_pool().await;
        let store = VoucherStore::new(pool.clone());

        // 1. Checkout creates durable pending order with QRIS payload
        let checkout_req = HotspotCheckoutRequest {
            order_id: Some("ORD-HOTSPOT-001".to_string()),
            customer_phone: Some("081234567890".to_string()),
            package_code: "HS-24H-10M".to_string(),
            count: 5,
            amount_idr: 25_000,
            time_limit_secs: 86_400,
            quota_bytes: Some(5_000_000_000),
            rate_limit: "5M/10M".to_string(),
        };
        let order = store.checkout(&checkout_req).await.unwrap();
        assert_eq!(order.order_id, "ORD-HOTSPOT-001");
        assert_eq!(order.status, "pending");
        assert_eq!(order.qris_reference, "QRIS-ORD-HOTSPOT-001");
        assert!(order.qris_payload.contains("ID.CO.QRIS.WWW"));

        // No vouchers minted before settlement
        assert_eq!(store.list().await.unwrap().len(), 0);

        // 2. Wrong settlement amount is rejected fail-closed
        let bad_settle = QrisSettlementPayload {
            order_id: Some("ORD-HOTSPOT-001".to_string()),
            qris_reference: None,
            paid_amount_idr: 10_000,
            settlement_status: "PAID".to_string(),
        };
        assert_eq!(
            store.settle_qris(&bad_settle).await,
            Err(VoucherError::AmountMismatch {
                expected: 25_000,
                actual: 10_000
            })
        );
        assert_eq!(store.list().await.unwrap().len(), 0);

        // 3. Valid QRIS settlement atomically activates batch in isp_vouchers & subscribers
        let settle_payload = QrisSettlementPayload {
            order_id: None,
            qris_reference: Some("QRIS-ORD-HOTSPOT-001".to_string()),
            paid_amount_idr: 25_000,
            settlement_status: "SETTLED".to_string(),
        };
        let settled = store.settle_qris(&settle_payload).await.unwrap();
        assert!(!settled.idempotent_replay);
        assert_eq!(settled.order.status, "settled");
        assert!(settled.order.settled_at.is_some());
        assert_eq!(settled.vouchers.len(), 5);
        assert_eq!(settled.radius_activated_count, 5);

        // Verify durable subscribers table has 5 active hotspot accounts with 5000k/10000k rates
        let sub_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM subscribers WHERE connection_type = 'hotspot' AND status = 'active' AND upload_kbps = 5000 AND download_kbps = 10000",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(sub_count, 5);

        // 4. Duplicate QRIS webhook replay is idempotent and does not mint extra vouchers
        let replay = store.settle_qris(&settle_payload).await.unwrap();
        assert!(replay.idempotent_replay);
        assert_eq!(replay.vouchers.len(), 5);
        assert_eq!(store.list().await.unwrap().len(), 5);
    }

    #[test]
    fn verifies_qris_hmac_signature_fail_closed() {
        let secret = "qris-webhook-secret-key-2026";
        let body = br#"{"qris_reference":"QRIS-ORD-1","paid_amount_idr":25000,"settlement_status":"PAID"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());

        assert!(verify_qris_signature(secret, body, &sig));
        assert!(verify_qris_signature(
            secret,
            body,
            &format!("sha256={sig}")
        ));
        assert!(!verify_qris_signature("wrong-secret", body, &sig));
        assert!(!verify_qris_signature(secret, body, "deadbeef"));
        assert!(!verify_qris_signature("", body, &sig));
    }
}
