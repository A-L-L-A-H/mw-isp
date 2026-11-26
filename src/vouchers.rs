//! Hotspot voucher generation and redemption state tracking.

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, Deserialize)]
pub struct BatchRequest {
    pub count: u32,
    pub code_length: Option<usize>,
    pub time_limit_secs: u64,
    pub quota_bytes: Option<u64>,
    pub rate_limit: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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

#[derive(Default)]
pub struct VoucherStore {
    inner: Mutex<BTreeMap<String, Voucher>>,
}

impl VoucherStore {
    pub fn create_batch(&self, req: &BatchRequest) -> Result<Vec<Voucher>, VoucherError> {
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
        let mut rng = rand::thread_rng();
        let mut store = self.inner.lock().expect("voucher store poisoned");
        let mut created = Vec::with_capacity(req.count as usize);
        while created.len() < req.count as usize {
            let code: String = (0..length)
                .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
                .collect();
            if store.contains_key(&code) {
                continue;
            }
            let voucher = Voucher {
                code: code.clone(),
                time_limit_secs: req.time_limit_secs,
                quota_bytes: req.quota_bytes,
                mikrotik_rate_limit: req.rate_limit.clone(),
                redeemed: false,
                redeemed_by: None,
            };
            store.insert(code, voucher.clone());
            created.push(voucher);
        }
        Ok(created)
    }

    pub fn redeem(&self, code: &str, username: &str) -> Result<Voucher, VoucherError> {
        let mut store = self.inner.lock().expect("voucher store poisoned");
        let voucher = store
            .get_mut(&code.to_ascii_uppercase())
            .ok_or(VoucherError::NotFound)?;
        if voucher.redeemed {
            return Err(VoucherError::AlreadyRedeemed);
        }
        voucher.redeemed = true;
        voucher.redeemed_by = Some(username.to_string());
        Ok(voucher.clone())
    }

    pub fn list(&self) -> Vec<Voucher> {
        self.inner
            .lock()
            .expect("voucher store poisoned")
            .values()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(count: u32) -> BatchRequest {
        BatchRequest {
            count,
            code_length: None,
            time_limit_secs: 3600,
            quota_bytes: Some(1_000_000),
            rate_limit: "2M/5M".into(),
        }
    }

    #[test]
    fn batch_generates_unique_codes_with_rate_limit() {
        let store = VoucherStore::default();
        let batch = store.create_batch(&request(50)).unwrap();
        assert_eq!(batch.len(), 50);
        assert_eq!(store.list().len(), 50);
        assert!(batch.iter().all(|v| v.code.len() == 10 && v.mikrotik_rate_limit == "2M/5M"));
    }

    #[test]
    fn redeem_once_only() {
        let store = VoucherStore::default();
        let code = store.create_batch(&request(1)).unwrap()[0].code.clone();
        assert_eq!(store.redeem(&code.to_lowercase(), "guest1").unwrap().redeemed_by.as_deref(), Some("guest1"));
        assert_eq!(store.redeem(&code, "guest2"), Err(VoucherError::AlreadyRedeemed));
        assert_eq!(store.redeem("NOPE", "g"), Err(VoucherError::NotFound));
    }

    #[test]
    fn validates_input() {
        let store = VoucherStore::default();
        assert_eq!(store.create_batch(&request(0)), Err(VoucherError::InvalidCount));
        let mut bad = request(1);
        bad.rate_limit = "fast".into();
        assert_eq!(store.create_batch(&bad), Err(VoucherError::InvalidRateLimit));
        assert!(valid_rate_limit("512k/1M"));
    }
}
