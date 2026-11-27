-- Migration 08: Prepaid voucher QRIS checkout orders (V20) and NAS outage hysteresis events (V50)

CREATE TABLE IF NOT EXISTS isp_voucher_orders (
    order_id TEXT PRIMARY KEY,
    package_name TEXT NOT NULL,
    voucher_count INTEGER NOT NULL,
    time_limit_secs INTEGER NOT NULL,
    quota_bytes INTEGER,
    mikrotik_rate_limit TEXT NOT NULL,
    amount_idr INTEGER NOT NULL,
    qris_payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'reserved',
    voucher_codes_json TEXT NOT NULL,
    payment_reference TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    settled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_isp_voucher_orders_status ON isp_voucher_orders(status);

CREATE TABLE IF NOT EXISTS isp_nas_outage_state (
    nas_ip TEXT PRIMARY KEY,
    tower_id TEXT,
    down_since_epoch_secs INTEGER,
    incident_id TEXT,
    notified INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS isp_outage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    nas_ip TEXT NOT NULL,
    tower_id TEXT,
    event_type TEXT NOT NULL,
    suppressed INTEGER NOT NULL DEFAULT 0,
    notified_subscribers INTEGER NOT NULL DEFAULT 0,
    message_id_locale TEXT NOT NULL,
    observed_at_epoch_secs INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_isp_outage_events_nas_ip ON isp_outage_events(nas_ip);
CREATE INDEX IF NOT EXISTS idx_isp_outage_events_incident ON isp_outage_events(incident_id);
