//! Prepaid Hotspot voucher purchase -> QRIS payment -> RADIUS batch activation (V20).
//!
//! Reserves a batch of hotspot vouchers upon checkout creation, transitions the
//! batch to `active` (and provisions RADIUS subscriber credentials) upon an
//! idempotent settled QRIS payment webhook, and serves a MikroTik login + QR
//! receipt via `GET /api/isp/vouchers/{order_id}/receipt`.

use crate::vouchers::{BatchRequest, VoucherError, VoucherStore};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

#[derive(Debug, Clone, Deserialize)]
pub struct CreateVoucherCheckoutRequest {
    pub order_id: String,
    pub package_name: String,
    pub count: u32,
    pub time_limit_secs: u64,
    pub quota_bytes: Option<u64>,
    pub rate_limit: String,
    pub amount_idr: u64,
    pub hotspot_login_base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoucherCheckoutOrder {
    pub order_id: String,
    pub package_name: String,
    pub count: u32,
    pub time_limit_secs: u64,
    pub quota_bytes: Option<u64>,
    pub mikrotik_rate_limit: String,
    pub amount_idr: u64,
    pub status: String,
    pub qris_payload: String,
    pub voucher_codes: Vec<String>,
    pub payment_reference: Option<String>,
    pub settled_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SettleVoucherOrderRequest {
    pub order_id: String,
    pub payment_reference: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoucherCredentialReceiptItem {
    pub code: String,
    pub username: String,
    pub password: String,
    pub mikrotik_login_url: String,
    pub qr_login_data: String,
    pub time_limit_secs: u64,
    pub quota_bytes: Option<u64>,
    pub mikrotik_rate_limit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoucherOrderReceipt {
    pub order_id: String,
    pub package_name: String,
    pub status: String,
    pub amount_idr: u64,
    pub qris_payload: String,
    pub payment_reference: Option<String>,
    pub settled_at: Option<String>,
    pub vouchers: Vec<VoucherCredentialReceiptItem>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VoucherCheckoutError {
    #[error("order_id and package_name must not be empty")]
    InvalidOrderInput,
    #[error("amount_idr must be > 0")]
    InvalidAmount,
    #[error("payment status is not settled")]
    PaymentNotSettled,
    #[error("voucher order not found")]
    OrderNotFound,
    #[error("voucher error: {0}")]
    Voucher(#[from] VoucherError),
    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for VoucherCheckoutError {
    fn from(err: sqlx::Error) -> Self {
        VoucherCheckoutError::Database(err.to_string())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct VoucherOrderRow {
    order_id: String,
    package_name: String,
    voucher_count: i64,
    time_limit_secs: i64,
    quota_bytes: Option<i64>,
    mikrotik_rate_limit: String,
    amount_idr: i64,
    qris_payload: String,
    status: String,
    voucher_codes_json: String,
    payment_reference: Option<String>,
    settled_at: Option<String>,
}

impl VoucherOrderRow {
    fn into_order(self) -> VoucherCheckoutOrder {
        let codes: Vec<String> = serde_json::from_str(&self.voucher_codes_json).unwrap_or_default();
        VoucherCheckoutOrder {
            order_id: self.order_id,
            package_name: self.package_name,
            count: self.voucher_count as u32,
            time_limit_secs: self.time_limit_secs as u64,
            quota_bytes: self.quota_bytes.map(|q| q as u64),
            mikrotik_rate_limit: self.mikrotik_rate_limit,
            amount_idr: self.amount_idr as u64,
            status: self.status,
            qris_payload: self.qris_payload,
            voucher_codes: codes,
            payment_reference: self.payment_reference,
            settled_at: self.settled_at,
        }
    }
}

fn rate_limit_to_kbps(rate_limit: &str) -> (i64, i64) {
    let parse_unit = |part: &str| -> i64 {
        let trimmed = part.trim();
        if let Some(num) = trimmed.strip_suffix(['G', 'g']) {
            num.parse::<i64>().unwrap_or(2) * 1_000_000
        } else if let Some(num) = trimmed.strip_suffix(['M', 'm']) {
            num.parse::<i64>().unwrap_or(2) * 1_000
        } else if let Some(num) = trimmed.strip_suffix(['K', 'k']) {
            num.parse::<i64>().unwrap_or(2048)
        } else {
            (trimmed.parse::<i64>().unwrap_or(2_048_000) / 1_000).max(64)
        }
    };
    match rate_limit.split_once('/') {
        Some((rx, tx)) => (parse_unit(tx), parse_unit(rx)),
        None => (5_000, 2_000),
    }
}

#[derive(Clone)]
pub struct VoucherCheckoutStore {
    pool: Pool<Sqlite>,
    vouchers: VoucherStore,
}

impl VoucherCheckoutStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        let vouchers = VoucherStore::new(pool.clone());
        Self { pool, vouchers }
    }

    /// Reserve a voucher batch in `reserved` state and generate a QRIS checkout payload.
    /// Idempotent by `order_id`: if the order already exists, returns the existing order.
    pub async fn create_checkout(
        &self,
        req: &CreateVoucherCheckoutRequest,
    ) -> Result<VoucherCheckoutOrder, VoucherCheckoutError> {
        let order_id = req.order_id.trim();
        let package_name = req.package_name.trim();
        if order_id.is_empty() || package_name.is_empty() {
            return Err(VoucherCheckoutError::InvalidOrderInput);
        }
        if req.amount_idr == 0 {
            return Err(VoucherCheckoutError::InvalidAmount);
        }

        if let Some(existing) = self.fetch_row(order_id).await? {
            return Ok(existing.into_order());
        }

        let batch = self
            .vouchers
            .create_batch(&BatchRequest {
                count: req.count,
                code_length: Some(10),
                time_limit_secs: req.time_limit_secs,
                quota_bytes: req.quota_bytes,
                rate_limit: req.rate_limit.clone(),
            })
            .await?;

        let codes: Vec<String> = batch.into_iter().map(|v| v.code).collect();
        let codes_json = serde_json::to_string(&codes).unwrap_or_else(|_| "[]".to_string());
        let qris_payload = format!(
            "00020101021226580016ID.CO.QRIS.WWW0118936009143000000000520448145303360540{}5802ID5915MOONWITNESS ISP6007JAKARTA62200116{}",
            req.amount_idr, order_id
        );

        sqlx::query(
            "INSERT INTO isp_voucher_orders (
                order_id, package_name, voucher_count, time_limit_secs, quota_bytes,
                mikrotik_rate_limit, amount_idr, qris_payload, status, voucher_codes_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'reserved', ?9)",
        )
        .bind(order_id)
        .bind(package_name)
        .bind(req.count as i64)
        .bind(req.time_limit_secs as i64)
        .bind(req.quota_bytes.map(|q| q as i64))
        .bind(&req.rate_limit)
        .bind(req.amount_idr as i64)
        .bind(&qris_payload)
        .bind(&codes_json)
        .execute(&self.pool)
        .await?;

        let row = self
            .fetch_row(order_id)
            .await?
            .ok_or(VoucherCheckoutError::OrderNotFound)?;
        Ok(row.into_order())
    }

    /// Transition a reserved voucher order to `active` upon a settled QRIS webhook
    /// and activate RADIUS hotspot credentials for every voucher code in the batch.
    pub async fn settle_webhook(
        &self,
        req: &SettleVoucherOrderRequest,
    ) -> Result<VoucherCheckoutOrder, VoucherCheckoutError> {
        let status_norm = req.status.trim().to_ascii_lowercase();
        if !matches!(
            status_norm.as_str(),
            "settled" | "settlement" | "paid" | "capture" | "success"
        ) {
            return Err(VoucherCheckoutError::PaymentNotSettled);
        }

        let order_id = req.order_id.trim();
        let row = self
            .fetch_row(order_id)
            .await?
            .ok_or(VoucherCheckoutError::OrderNotFound)?;

        if row.status == "active" {
            return Ok(row.into_order());
        }

        let codes: Vec<String> = serde_json::from_str(&row.voucher_codes_json).unwrap_or_default();
        let (download_kbps, upload_kbps) = rate_limit_to_kbps(&row.mikrotik_rate_limit);
        let quota_bytes = row.quota_bytes.unwrap_or(0);

        let mut tx = self.pool.begin().await?;
        for code in &codes {
            // Redeem voucher in isp_vouchers and provision active RADIUS hotspot subscriber
            sqlx::query(
                "UPDATE isp_vouchers
                 SET redeemed = 1, redeemed_by = ?1, redeemed_at = datetime('now')
                 WHERE code = ?2",
            )
            .bind(format!("qris:{order_id}"))
            .bind(code)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO subscribers (
                    username, password, connection_type, download_kbps, upload_kbps, status, quota_bytes
                 ) VALUES (?1, ?2, 'hotspot', ?3, ?4, 'active', ?5)
                 ON CONFLICT(username) DO UPDATE SET
                    password = excluded.password,
                    connection_type = 'hotspot',
                    download_kbps = excluded.download_kbps,
                    upload_kbps = excluded.upload_kbps,
                    status = 'active',
                    quota_bytes = excluded.quota_bytes,
                    updated_at = datetime('now')",
            )
            .bind(code)
            .bind(code)
            .bind(download_kbps)
            .bind(upload_kbps)
            .bind(quota_bytes)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            "UPDATE isp_voucher_orders
             SET status = 'active',
                 payment_reference = ?1,
                 settled_at = datetime('now')
             WHERE order_id = ?2",
        )
        .bind(req.payment_reference.trim())
        .bind(order_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let updated = self
            .fetch_row(order_id)
            .await?
            .ok_or(VoucherCheckoutError::OrderNotFound)?;
        Ok(updated.into_order())
    }

    /// Return the receipt for `GET /api/isp/vouchers/{order_id}/receipt` containing
    /// MikroTik hotspot login links and QR login payloads.
    pub async fn get_receipt(
        &self,
        order_id: &str,
        hotspot_base_url: Option<&str>,
    ) -> Result<VoucherOrderReceipt, VoucherCheckoutError> {
        let row = self
            .fetch_row(order_id.trim())
            .await?
            .ok_or(VoucherCheckoutError::OrderNotFound)?;
        let order = row.into_order();
        let base = hotspot_base_url
            .unwrap_or("http://hotspot.mw-isp.id/login")
            .trim_end_matches('/');

        let vouchers = order
            .voucher_codes
            .iter()
            .map(|code| {
                let login_url = format!("{base}?username={code}&password={code}");
                let qr_login_data =
                    format!("WIFI:S:MoonWitness-Hotspot;T:nopass;H:false;;LOGIN:{login_url}");
                VoucherCredentialReceiptItem {
                    code: code.clone(),
                    username: code.clone(),
                    password: code.clone(),
                    mikrotik_login_url: login_url,
                    qr_login_data,
                    time_limit_secs: order.time_limit_secs,
                    quota_bytes: order.quota_bytes,
                    mikrotik_rate_limit: order.mikrotik_rate_limit.clone(),
                }
            })
            .collect();

        Ok(VoucherOrderReceipt {
            order_id: order.order_id,
            package_name: order.package_name,
            status: order.status,
            amount_idr: order.amount_idr,
            qris_payload: order.qris_payload,
            payment_reference: order.payment_reference,
            settled_at: order.settled_at,
            vouchers,
        })
    }

    async fn fetch_row(&self, order_id: &str) -> Result<Option<VoucherOrderRow>, sqlx::Error> {
        sqlx::query_as(
            "SELECT order_id, package_name, voucher_count, time_limit_secs, quota_bytes,
                    mikrotik_rate_limit, amount_idr, qris_payload, status, voucher_codes_json,
                    payment_reference, settled_at
             FROM isp_voucher_orders
             WHERE order_id = ?1",
        )
        .bind(order_id)
        .fetch_optional(&self.pool)
        .await
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
    async fn reserves_batch_on_checkout_and_activates_on_settled_webhook_with_receipt() {
        let pool = setup_test_pool().await;
        let store = VoucherCheckoutStore::new(pool.clone());

        let checkout = store
            .create_checkout(&CreateVoucherCheckoutRequest {
                order_id: "ORD-QRIS-001".to_string(),
                package_name: "Hotspot Harian 5GB".to_string(),
                count: 2,
                time_limit_secs: 86_400,
                quota_bytes: Some(5_000_000_000),
                rate_limit: "5M/10M".to_string(),
                amount_idr: 15_000,
                hotspot_login_base_url: None,
            })
            .await
            .unwrap();

        assert_eq!(checkout.status, "reserved");
        assert_eq!(checkout.voucher_codes.len(), 2);
        assert!(checkout.qris_payload.contains("ORD-QRIS-001"));

        // Settled webhook transitions order to active and provisions RADIUS subscribers.
        let settled = store
            .settle_webhook(&SettleVoucherOrderRequest {
                order_id: "ORD-QRIS-001".to_string(),
                payment_reference: "MIDTRANS-TX-991".to_string(),
                status: "settlement".to_string(),
            })
            .await
            .unwrap();

        assert_eq!(settled.status, "active");
        assert_eq!(
            settled.payment_reference.as_deref(),
            Some("MIDTRANS-TX-991")
        );
        assert!(settled.settled_at.is_some());

        // Verify RADIUS subscriber rows are active in SQLite.
        let active_subs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM subscribers WHERE connection_type = 'hotspot' AND status = 'active'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active_subs, 2);

        // Verify receipt endpoint payload returns MikroTik login URL & QR data.
        let receipt = store.get_receipt("ORD-QRIS-001", None).await.unwrap();
        assert_eq!(receipt.status, "active");
        assert_eq!(receipt.vouchers.len(), 2);
        assert!(
            receipt.vouchers[0]
                .mikrotik_login_url
                .contains(&receipt.vouchers[0].code)
        );
        assert!(receipt.vouchers[0].qr_login_data.contains("WIFI:S:"));
    }
}
