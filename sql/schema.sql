-- SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
-- KeySentry reference DDL. Mirrors the SQLite schema created by
-- keysentry/core/storage.py (SCHEMA). Timestamps are ISO-8601 TEXT; meta and
-- payload hold JSON documents.

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    detector_id TEXT,
    title TEXT,
    severity TEXT,
    surface TEXT,
    path TEXT,
    line INTEGER,
    secret_masked TEXT,
    entropy REAL,
    fingerprint TEXT,
    status TEXT,
    owner TEXT,
    created_at TEXT,
    updated_at TEXT,
    meta TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    kind TEXT,
    surface TEXT,
    payload TEXT,
    ts TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    channel TEXT,
    message TEXT,
    status TEXT,
    ts TEXT
);

CREATE TABLE IF NOT EXISTS allowlist (
    fingerprint TEXT PRIMARY KEY,
    reason TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS remediations (
    id TEXT PRIMARY KEY,
    finding_id TEXT,
    action TEXT,
    detail TEXT,
    ts TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);