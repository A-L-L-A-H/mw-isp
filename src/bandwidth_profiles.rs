//! Bandwidth profile and RouterOS `MikroTik-Rate-Limit` policy builder.
//!
//! Generates structured MikroTik-Rate-Limit strings formatted per RouterOS documentation:
//! `rx-rate[/tx-rate] [rx-burst-rate[/tx-burst-rate] [rx-burst-threshold[/tx-burst-threshold] [rx-burst-time[/tx-burst-time] [priority] [rx-rate-min[/tx-rate-min]]]]`
//!
//! Supports:
//! - Standard rate limits (rx/tx in kbps/Mbps/Gbps)
//! - Burst policies (burst rates, thresholds, and burst duration in seconds)
//! - Fair Usage Policy (FUP) throttling based on quota consumption tiers
//! - Walled-garden / Isolir bandwidth profiles for captive portal redirection

use serde::{Deserialize, Serialize};

pub const DEFAULT_WALLED_GARDEN_RX_KBPS: u64 = 256;
pub const DEFAULT_WALLED_GARDEN_TX_KBPS: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatePair {
    pub upload_kbps: u64,
    pub download_kbps: u64,
}

impl RatePair {
    pub fn new(upload_kbps: u64, download_kbps: u64) -> Self {
        Self {
            upload_kbps,
            download_kbps,
        }
    }

    pub fn to_routeros_string(&self) -> String {
        format!("{}k/{}k", self.upload_kbps, self.download_kbps)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurstConfig {
    pub burst_rate: RatePair,
    pub threshold: RatePair,
    pub time_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FupTier {
    FullSpeed,
    Tier1Throttle, // e.g. 50%
    Tier2Throttle, // e.g. 20%
    Exhausted,     // dropped to minimal speed
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthPolicy {
    pub base_rate: RatePair,
    pub burst: Option<BurstConfig>,
    pub priority: Option<u8>,
    pub min_rate: Option<RatePair>,
    pub walled_garden: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BandwidthPolicyError {
    #[error("rates must be greater than zero")]
    ZeroRate,
    #[error("burst duration must be > 0 and <= 86400 seconds")]
    InvalidBurstTime,
    #[error("priority must be between 1 and 8")]
    InvalidPriority,
    #[error("burst rate must be greater than or equal to base rate")]
    BurstRateTooLow,
}

impl Default for BandwidthPolicy {
    fn default() -> Self {
        Self {
            base_rate: RatePair::new(10_240, 20_480), // 10M/20M
            burst: None,
            priority: None,
            min_rate: None,
            walled_garden: false,
        }
    }
}

impl BandwidthPolicy {
    pub fn new(upload_kbps: u64, download_kbps: u64) -> Self {
        Self {
            base_rate: RatePair::new(upload_kbps, download_kbps),
            ..Default::default()
        }
    }

    pub fn walled_garden() -> Self {
        Self {
            base_rate: RatePair::new(DEFAULT_WALLED_GARDEN_RX_KBPS, DEFAULT_WALLED_GARDEN_TX_KBPS),
            burst: None,
            priority: Some(8), // Lowest priority
            min_rate: None,
            walled_garden: true,
        }
    }

    pub fn with_burst(
        mut self,
        burst_upload_kbps: u64,
        burst_download_kbps: u64,
        threshold_upload_kbps: u64,
        threshold_download_kbps: u64,
        time_seconds: u64,
    ) -> Self {
        self.burst = Some(BurstConfig {
            burst_rate: RatePair::new(burst_upload_kbps, burst_download_kbps),
            threshold: RatePair::new(threshold_upload_kbps, threshold_download_kbps),
            time_seconds,
        });
        self
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn with_min_rate(mut self, min_upload_kbps: u64, min_download_kbps: u64) -> Self {
        self.min_rate = Some(RatePair::new(min_upload_kbps, min_download_kbps));
        self
    }

    pub fn apply_fup(&self, tier: FupTier) -> Self {
        let mut policy = self.clone();
        match tier {
            FupTier::FullSpeed => {}
            FupTier::Tier1Throttle => {
                policy.base_rate.upload_kbps = (policy.base_rate.upload_kbps / 2).max(512);
                policy.base_rate.download_kbps = (policy.base_rate.download_kbps / 2).max(1024);
                policy.burst = None; // Disable burst during throttle
            }
            FupTier::Tier2Throttle => {
                policy.base_rate.upload_kbps = (policy.base_rate.upload_kbps / 5).max(256);
                policy.base_rate.download_kbps = (policy.base_rate.download_kbps / 5).max(512);
                policy.burst = None;
            }
            FupTier::Exhausted => {
                policy.base_rate.upload_kbps = 128;
                policy.base_rate.download_kbps = 256;
                policy.burst = None;
                policy.min_rate = None;
                policy.priority = Some(8);
            }
        }
        policy
    }

    pub fn build_mikrotik_rate_limit(&self) -> Result<String, BandwidthPolicyError> {
        if self.base_rate.upload_kbps == 0 || self.base_rate.download_kbps == 0 {
            return Err(BandwidthPolicyError::ZeroRate);
        }

        let mut parts = vec![self.base_rate.to_routeros_string()];

        if let Some(burst) = &self.burst {
            if burst.time_seconds == 0 || burst.time_seconds > 86400 {
                return Err(BandwidthPolicyError::InvalidBurstTime);
            }
            if burst.burst_rate.upload_kbps < self.base_rate.upload_kbps
                || burst.burst_rate.download_kbps < self.base_rate.download_kbps
            {
                return Err(BandwidthPolicyError::BurstRateTooLow);
            }

            parts.push(burst.burst_rate.to_routeros_string());
            parts.push(burst.threshold.to_routeros_string());
            parts.push(format!("{}s/{}s", burst.time_seconds, burst.time_seconds));

            if let Some(prio) = self.priority {
                if !(1..=8).contains(&prio) {
                    return Err(BandwidthPolicyError::InvalidPriority);
                }
                parts.push(prio.to_string());

                if let Some(min_rate) = &self.min_rate {
                    parts.push(min_rate.to_routeros_string());
                }
            } else if let Some(min_rate) = &self.min_rate {
                // If min_rate is specified without priority, RouterOS requires priority field (default 8)
                parts.push("8".to_string());
                parts.push(min_rate.to_routeros_string());
            }
        } else if let Some(prio) = self.priority {
            if !(1..=8).contains(&prio) {
                return Err(BandwidthPolicyError::InvalidPriority);
            }
            // Without burst, RouterOS still allows rx-rate/tx-rate priority min-rate
            // But per RouterOS spec, omitting burst requires empty or explicit slots, or simple rate-limit.
            // When only priority/min_rate are present without burst, we format:
            // rx/tx 0/0 0/0 0/0 prio min-rate
            if let Some(min_rate) = &self.min_rate {
                parts.push("0k/0k".to_string());
                parts.push("0k/0k".to_string());
                parts.push("0s/0s".to_string());
                parts.push(prio.to_string());
                parts.push(min_rate.to_routeros_string());
            }
        }

        Ok(parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_rate_limit_builds_correctly() {
        let policy = BandwidthPolicy::new(10_240, 20_480);
        assert_eq!(policy.build_mikrotik_rate_limit().unwrap(), "10240k/20480k");
    }

    #[test]
    fn burst_rate_limit_formats_all_slots() {
        let policy = BandwidthPolicy::new(10_000, 20_000)
            .with_burst(20_000, 40_000, 8_000, 16_000, 30)
            .with_priority(5)
            .with_min_rate(2_000, 4_000);

        let output = policy.build_mikrotik_rate_limit().unwrap();
        assert_eq!(
            output,
            "10000k/20000k 20000k/40000k 8000k/16000k 30s/30s 5 2000k/4000k"
        );
    }

    #[test]
    fn walled_garden_policy() {
        let policy = BandwidthPolicy::walled_garden();
        assert!(policy.walled_garden);
        assert_eq!(policy.base_rate.upload_kbps, 256);
        assert_eq!(policy.base_rate.download_kbps, 256);
        assert_eq!(policy.build_mikrotik_rate_limit().unwrap(), "256k/256k");
    }

    #[test]
    fn fup_throttling_stages() {
        let policy = BandwidthPolicy::new(10_000, 20_000).with_burst(20_000, 40_000, 8_000, 16_000, 10);
        let tier1 = policy.apply_fup(FupTier::Tier1Throttle);
        assert_eq!(tier1.base_rate.upload_kbps, 5_000);
        assert_eq!(tier1.base_rate.download_kbps, 10_000);
        assert!(tier1.burst.is_none());

        let tier2 = policy.apply_fup(FupTier::Tier2Throttle);
        assert_eq!(tier2.base_rate.upload_kbps, 2_000);
        assert_eq!(tier2.base_rate.download_kbps, 4_000);

        let exhausted = policy.apply_fup(FupTier::Exhausted);
        assert_eq!(exhausted.base_rate.upload_kbps, 128);
        assert_eq!(exhausted.base_rate.download_kbps, 256);
    }

    #[test]
    fn validates_invalid_configurations() {
        let zero = BandwidthPolicy::new(0, 100);
        assert_eq!(zero.build_mikrotik_rate_limit(), Err(BandwidthPolicyError::ZeroRate));

        let bad_burst = BandwidthPolicy::new(10_000, 20_000).with_burst(5_000, 10_000, 1_000, 2_000, 10);
        assert_eq!(
            bad_burst.build_mikrotik_rate_limit(),
            Err(BandwidthPolicyError::BurstRateTooLow)
        );

        let bad_time = BandwidthPolicy::new(10_000, 20_000).with_burst(20_000, 40_000, 8_000, 16_000, 0);
        assert_eq!(
            bad_time.build_mikrotik_rate_limit(),
            Err(BandwidthPolicyError::InvalidBurstTime)
        );
    }
}
