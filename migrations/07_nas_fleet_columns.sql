-- Migration 07: Add tower_id, latency_ms, last_health_check_at to nas_clients

ALTER TABLE nas_clients ADD COLUMN tower_id TEXT;
ALTER TABLE nas_clients ADD COLUMN latency_ms INTEGER;
ALTER TABLE nas_clients ADD COLUMN last_health_check_at TEXT;

CREATE INDEX IF NOT EXISTS idx_nas_clients_tower_id ON nas_clients(tower_id);
