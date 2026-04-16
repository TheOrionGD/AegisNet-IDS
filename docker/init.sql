-- =========================================
-- CNS / AEGISNET SIEM - DATABASE INIT
-- =========================================

-- ================================
-- EXTENSIONS
-- ================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ================================
-- SECURITY EVENTS
-- ================================
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source VARCHAR(255) NOT NULL,
    event_type VARCHAR(255) NOT NULL,
    severity INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 10),
    message TEXT,
    raw_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ================================
-- INCIDENTS
-- ================================
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 10),
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    assignee VARCHAR(255)
);

-- ================================
-- INCIDENT ↔ EVENTS MAPPING
-- ================================
CREATE TABLE IF NOT EXISTS incident_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id UUID NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ================================
-- ANOMALIES
-- ================================
CREATE TABLE IF NOT EXISTS anomalies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    score DOUBLE PRECISION NOT NULL,
    features JSONB,
    prediction INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ================================
-- USERS
-- ================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'analyst',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

-- ================================
-- INDEXES (PERFORMANCE)
-- ================================
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source ON security_events(source);
CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_anomalies_score ON anomalies(score);

CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events(event_id);

-- ================================
-- AUTO UPDATE updated_at TRIGGER
-- ================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_incidents ON incidents;

CREATE TRIGGER trg_update_incidents
BEFORE UPDATE ON incidents
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- ================================
-- DEFAULT ADMIN USER
-- ================================
INSERT INTO users (username, email, password_hash, role)
VALUES (
    'admin',
    'admin@cns.local',
    '$2b$12$8HcA68ji0EXJeIGVfKDh2uSSmeDji3B7s5v6OSVkrdBJFWPse653y', -- password: AEGISNET-IDS@SECURE
    'admin'
)
ON CONFLICT (username) DO NOTHING;

-- ================================
-- SAMPLE DATA (OPTIONAL BUT USEFUL)
-- ================================

-- Sample security events
INSERT INTO security_events (source, event_type, severity, message, raw_data)
VALUES
('firewall', 'port_scan', 7, 'Multiple port scan detected', '{"ip":"192.168.1.10"}'),
('auth_system', 'failed_login', 5, 'Multiple failed login attempts', '{"user":"root"}'),
('ids', 'intrusion_detected', 9, 'Possible intrusion detected', '{"signature":"SQL Injection"}')
ON CONFLICT DO NOTHING;

-- Sample incident
INSERT INTO incidents (title, description, severity, status, assignee)
VALUES
('Potential Intrusion Attack', 'Detected suspicious activity from IDS', 9, 'open', 'analyst1')
ON CONFLICT DO NOTHING;

-- ================================
-- DONE
-- ================================