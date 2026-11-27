-- Migration 06: durable vouchers and CoA audit tables

CREATE TABLE IF NOT EXISTS isp_vouchers (
    code TEXT PRIMARY KEY,
    time_limit_secs INTEGER NOT NULL,
    quota_bytes INTEGER,
    mikrotik_rate_limit TEXT NOT NULL,
    redeemed INTEGER NOT NULL DEFAULT 0,
    redeemed_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    redeemed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_isp_vouchers_redeemed ON isp_vouchers(redeemed);

CREATE TABLE IF NOT EXISTS isp_coa_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_row_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    nas_ip TEXT,
    action TEXT NOT NULL DEFAULT 'disconnect',
    sent INTEGER NOT NULL DEFAULT 0,
    ack INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_isp_coa_audit_session_row ON isp_coa_audit(session_row_id);
CREATE INDEX IF NOT EXISTS idx_isp_coa_audit_username ON isp_coa_audit(username);
CREATE INDEX IF NOT EXISTS idx_isp_coa_audit_created_at ON isp_coa_audit(created_at DESC);
