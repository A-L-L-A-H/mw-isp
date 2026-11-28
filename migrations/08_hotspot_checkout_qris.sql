-- Migration 08: Prepaid Hotspot voucher checkout & QRIS settlement orders

ALTER TABLE isp_vouchers ADD COLUMN order_id TEXT;
ALTER TABLE isp_vouchers ADD COLUMN status TEXT NOT NULL DEFAULT 'active';

CREATE INDEX IF NOT EXISTS idx_isp_vouchers_order_id ON isp_vouchers(order_id);
CREATE INDEX IF NOT EXISTS idx_isp_vouchers_status ON isp_vouchers(status);

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
);

CREATE INDEX IF NOT EXISTS idx_hotspot_voucher_orders_status ON hotspot_voucher_orders(status);
CREATE INDEX IF NOT EXISTS idx_hotspot_voucher_orders_qris_ref ON hotspot_voucher_orders(qris_reference);
