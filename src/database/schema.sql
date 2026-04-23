-- Advanced Cybersecurity Sandbox Platform
-- PostgreSQL Database Schema
-- Version: 1.0.0

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- SAMPLES TABLE
-- Stores information about submitted samples for analysis
-- ============================================================================
CREATE TABLE samples (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sha256_hash CHAR(64) NOT NULL UNIQUE,
    sha1_hash CHAR(40) NOT NULL,
    md5_hash CHAR(32) NOT NULL,
    ssdeep_hash TEXT,
    tlsh_hash TEXT,

    -- File metadata
    file_name TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    file_type TEXT,
    mime_type TEXT,

    -- Submission metadata
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    submitted_by UUID REFERENCES users(id),
    source_type TEXT CHECK (source_type IN ('api', 'email', 'honeypot', 'ti_feed', 'manual')),
    priority INTEGER DEFAULT 5 CHECK (priority BETWEEN 1 AND 10),

    -- Analysis status
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'queued', 'analyzing', 'completed', 'failed', 'deferred')),
    sandbox_id UUID REFERENCES sandboxes(id),
    analysis_started_at TIMESTAMP WITH TIME ZONE,
    analysis_completed_at TIMESTAMP WITH TIME ZONE,

    -- Verdict
    verdict TEXT CHECK (verdict IN ('malicious', 'suspicious', 'benign', 'unknown', 'error')),
    confidence_score DECIMAL(5, 4) CHECK (confidence_score BETWEEN 0 AND 1),
    ml_score DECIMAL(5, 4),

    -- Storage
    storage_path TEXT NOT NULL,
    encrypted BOOLEAN DEFAULT TRUE,

    -- Indexes
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_samples_sha256 ON samples(sha256_hash);
CREATE INDEX idx_samples_status ON samples(status);
CREATE INDEX idx_samples_verdict ON samples(verdict);
CREATE INDEX idx_samples_submitted_at ON samples(submitted_at);
CREATE INDEX idx_samples_priority ON samples(priority DESC, submitted_at ASC);

-- ============================================================================
-- SANDBOXES TABLE
-- Registered sandbox instances for analysis
-- ============================================================================
CREATE TABLE sandboxes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL UNIQUE,
    sandbox_type TEXT NOT NULL CHECK (sandbox_type IN ('capev2', 'drakvuf', 'e2b', 'kasm', 'gvisor', 'custom')),

    -- Configuration
    os_type TEXT CHECK (os_type IN ('windows', 'linux', 'android', 'macos')),
    os_version TEXT,
    architecture TEXT CHECK (architecture IN ('x86', 'x86_64', 'arm', 'arm64')),

    -- Capabilities
    capabilities JSONB DEFAULT '[]'::jsonb,
    deception_artifacts JSONB DEFAULT '{}'::jsonb,

    -- Status
    status TEXT DEFAULT 'offline' CHECK (status IN ('online', 'offline', 'busy', 'maintenance', 'compromised')),
    last_heartbeat TIMESTAMP WITH TIME ZONE,

    -- Statistics
    total_analyses INTEGER DEFAULT 0,
    successful_analyses INTEGER DEFAULT 0,
    failed_analyses INTEGER DEFAULT 0,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sandboxes_status ON sandboxes(status);
CREATE INDEX idx_sandboxes_type ON sandboxes(sandbox_type);

-- ============================================================================
-- BEHAVIORS TABLE
-- Records behavioral observations during analysis
-- ============================================================================
CREATE TABLE behaviors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sample_id UUID NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    sandbox_id UUID REFERENCES sandboxes(id),

    -- Timing
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    relative_time_ms INTEGER,

    -- Behavior type
    behavior_type TEXT NOT NULL CHECK (behavior_type IN (
        'process', 'file', 'registry', 'network', 'memory',
        'persistence', 'evasion', 'injection', 'exfiltration', 'c2'
    )),

    -- Severity
    severity TEXT CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),

    -- Description
    description TEXT NOT NULL,

    -- Raw data
    raw_data JSONB DEFAULT '{}'::jsonb,

    -- MITRE ATT&CK mapping
    mitre_attack_id TEXT,
    mitre_attack_tactic TEXT,
    mitre_attack_technique TEXT,

    -- Sigma rule match
    sigma_rule_id TEXT,
    sigma_rule_name TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_behaviors_sample_id ON behaviors(sample_id);
CREATE INDEX idx_behaviors_type ON behaviors(behavior_type);
CREATE INDEX idx_behaviors_severity ON behaviors(severity);
CREATE INDEX idx_behaviors_mitre ON behaviors(mitre_attack_id) WHERE mitre_attack_id IS NOT NULL;
CREATE INDEX idx_behaviors_timestamp ON behaviors(timestamp);

-- ============================================================================
-- IOCS TABLE
-- Indicators of Compromise extracted from analysis
-- ============================================================================
CREATE TABLE iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sample_id UUID NOT NULL REFERENCES samples(id) ON DELETE CASCADE,

    -- IOC type
    ioc_type TEXT NOT NULL CHECK (ioc_type IN (
        'ip', 'domain', 'url', 'email', 'file_hash',
        'mutex', 'registry_key', 'file_path', 'user_agent',
        'certificate', 'mac_address', 'filename', 'filepath'
    )),

    -- IOC value
    value TEXT NOT NULL,
    value_normalized TEXT,

    -- Context
    description TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE,

    -- Confidence
    confidence TEXT CHECK (confidence IN ('low', 'medium', 'high')),
    confidence_score DECIMAL(5, 4),

    -- Threat intelligence enrichment
    ti_enriched BOOLEAN DEFAULT FALSE,
    ti_sources JSONB DEFAULT '[]'::jsonb,
    ti_tags TEXT[] DEFAULT '{}',

    -- MISP sync
    misp_event_id UUID,
    misp_attribute_id UUID,
    misp_synced_at TIMESTAMP WITH TIME ZONE,

    -- TLP marking
    tlp TEXT CHECK (tlp IN ('white', 'green', 'amber', 'red')),

    -- Expiration
    expires_at TIMESTAMP WITH TIME ZONE,
    expired BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_ioc UNIQUE (ioc_type, value)
);

CREATE INDEX idx_iocs_sample_id ON iocs(sample_id);
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_iocs_type_value ON iocs(ioc_type, value);
CREATE INDEX idx_iocs_misp ON iocs(misp_event_id) WHERE misp_event_id IS NOT NULL;
CREATE INDEX idx_iocs_tlp ON iocs(tlp);

-- ============================================================================
-- ANALYSIS REPORTS TABLE
-- Complete analysis reports from sandbox engines
-- ============================================================================
CREATE TABLE analysis_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sample_id UUID NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    sandbox_id UUID REFERENCES sandboxes(id),

    -- Report metadata
    report_format TEXT CHECK (report_format IN ('capev2', 'drakvuf', 'e2b', 'custom', 'json')),
    report_version TEXT,

    -- Report content
    report_data JSONB NOT NULL,

    -- Summary
    summary TEXT,
    signature_matches JSONB DEFAULT '[]'::jsonb,
    mitre_attack_mapping JSONB DEFAULT '[]'::jsonb,

    -- Files generated
    screenshots INTEGER DEFAULT 0,
    pcaps INTEGER DEFAULT 0,
    memory_dumps INTEGER DEFAULT 0,

    -- Processing
    processing_status TEXT DEFAULT 'pending' CHECK (processing_status IN ('pending', 'processing', 'completed', 'failed')),
    processing_error TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_analysis_reports_sample_id ON analysis_reports(sample_id);
CREATE INDEX idx_analysis_reports_sandbox_id ON analysis_reports(sandbox_id);
CREATE INDEX idx_analysis_reports_status ON analysis_reports(processing_status);

-- ============================================================================
-- USERS TABLE
-- System users (analysts, admins, API clients)
-- ============================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,

    -- Authentication
    password_hash TEXT,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT,

    -- Authorization
    role TEXT NOT NULL CHECK (role IN ('analyst', 'senior_analyst', 'admin', 'api_client', 'readonly')),
    permissions JSONB DEFAULT '[]'::jsonb,

    -- Profile
    full_name TEXT,
    organization TEXT,

    -- Status
    active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,

    -- API
    api_key_hash TEXT,
    api_key_expires_at TIMESTAMP WITH TIME ZONE,
    api_rate_limit INTEGER DEFAULT 1000,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_api_key ON users(api_key_hash) WHERE api_key_hash IS NOT NULL;

-- ============================================================================
-- SUBMISSION QUEUE TABLE
-- Queue for pending sample analysis
-- ============================================================================
CREATE TABLE submission_queue (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sample_id UUID NOT NULL REFERENCES samples(id) ON DELETE CASCADE,

    -- Queue configuration
    priority INTEGER DEFAULT 5 CHECK (priority BETWEEN 1 AND 10),
    requested_sandbox_type TEXT,
    requested_os_type TEXT,
    custom_config JSONB DEFAULT '{}'::jsonb,

    -- Queue status
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'assigned', 'processing', 'completed', 'cancelled', 'failed')),
    assigned_sandbox_id UUID REFERENCES sandboxes(id),

    -- Timing
    queued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_at TIMESTAMP WITH TIME ZONE,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Error handling
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    error_message TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_submission_queue_status ON submission_queue(status);
CREATE INDEX idx_submission_queue_priority ON submission_queue(priority DESC, queued_at ASC);
CREATE INDEX idx_submission_queue_sandbox ON submission_queue(assigned_sandbox_id);

-- ============================================================================
-- AUDIT LOG TABLE
-- Immutable audit trail for compliance
-- ============================================================================
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Actor
    user_id UUID REFERENCES users(id),
    user_agent TEXT,
    ip_address INET,

    -- Action
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id UUID,

    -- Details
    details JSONB DEFAULT '{}'::jsonb,
    old_values JSONB,
    new_values JSONB,

    -- Result
    status TEXT CHECK (status IN ('success', 'failure', 'partial')),
    error_message TEXT,

    -- Immutable timestamp
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);

-- ============================================================================
-- THREAT INTELLIGENCE FEEDS TABLE
-- External TI feed configurations and cache
-- ============================================================================
CREATE TABLE ti_feeds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL UNIQUE,

    -- Feed configuration
    feed_type TEXT CHECK (feed_type IN ('misp', 'openc ti', 'virustotal', 'alienvault', 'custom')),
    feed_url TEXT,
    api_key TEXT,

    -- Sync configuration
    sync_interval_minutes INTEGER DEFAULT 60,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    next_sync_at TIMESTAMP WITH TIME ZONE,
    sync_status TEXT CHECK (sync_status IN ('idle', 'syncing', 'success', 'failed')),
    sync_error TEXT,

    -- Statistics
    total_indicators INTEGER DEFAULT 0,
    new_indicators_last_sync INTEGER DEFAULT 0,

    -- Enable status
    enabled BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- YARA RULES TABLE
-- YARA rule storage and versioning
-- ============================================================================
CREATE TABLE yara_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,

    -- Rule content
    rule_content TEXT NOT NULL,
    rule_hash TEXT NOT NULL,

    -- Metadata
    author TEXT,
    description TEXT,
    tags TEXT[] DEFAULT '{}',
    source TEXT,

    -- Status
    active BOOLEAN DEFAULT TRUE,
    deprecated BOOLEAN DEFAULT FALSE,

    -- Statistics
    match_count INTEGER DEFAULT 0,
    last_matched_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT unique_rule UNIQUE (name, version)
);

CREATE INDEX idx_yara_rules_active ON yara_rules(active) WHERE active = TRUE;
CREATE INDEX idx_yara_rules_tags ON yara_rules USING GIN(tags);

-- ============================================================================
-- SIGMA RULES TABLE
-- Sigma detection rules for behavioral analysis
-- ============================================================================
CREATE TABLE sigma_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sigma_uuid UUID NOT NULL UNIQUE,

    -- Rule metadata
    title TEXT NOT NULL,
    status TEXT CHECK (status IN ('stable', 'test', 'experimental', 'deprecated')),
    level TEXT CHECK (level IN ('info', 'low', 'medium', 'high', 'critical')),

    -- Rule content
    rule_data JSONB NOT NULL,

    -- Classification
    tags TEXT[] DEFAULT '{}',
    mitre_attack_ids TEXT[] DEFAULT '{}',
    logsource JSONB,

    -- Status
    active BOOLEAN DEFAULT TRUE,

    -- Statistics
    match_count INTEGER DEFAULT 0,
    last_matched_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sigma_rules_active ON sigma_rules(active) WHERE active = TRUE;
CREATE INDEX idx_sigma_rules_level ON sigma_rules(level);
CREATE INDEX idx_sigma_rules_mitre ON sigma_rules USING GIN(mitre_attack_ids);

-- ============================================================================
-- ML MODEL VERSIONS TABLE
-- Track ML model versions and performance metrics
-- ============================================================================
CREATE TABLE ml_models (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_name TEXT NOT NULL,
    version TEXT NOT NULL,

    -- Model metadata
    model_type TEXT,
    framework TEXT,
    training_date TIMESTAMP WITH TIME ZONE,

    -- Storage
    model_path TEXT,
    model_hash TEXT,

    -- Performance metrics
    precision DECIMAL(5, 4),
    recall DECIMAL(5, 4),
    f1_score DECIMAL(5, 4),
    auc_roc DECIMAL(5, 4),

    -- Training data
    training_samples INTEGER,
    training_data_hash TEXT,

    -- Deployment
    deployed BOOLEAN DEFAULT FALSE,
    deployed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ml_models_deployed ON ml_models(deployed) WHERE deployed = TRUE;
CREATE INDEX idx_ml_models_name ON ml_models(model_name);

-- ============================================================================
-- TRIGGER FUNCTIONS
-- ============================================================================

-- Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to tables with updated_at
CREATE TRIGGER update_samples_updated_at BEFORE UPDATE ON samples
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sandboxes_updated_at BEFORE UPDATE ON sandboxes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_iocs_updated_at BEFORE UPDATE ON iocs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_analysis_reports_updated_at BEFORE UPDATE ON analysis_reports
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_ti_feeds_updated_at BEFORE UPDATE ON ti_feeds
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_yara_rules_updated_at BEFORE UPDATE ON yara_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sigma_rules_updated_at BEFORE UPDATE ON sigma_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Sample analysis summary view
CREATE VIEW v_sample_analysis_summary AS
SELECT
    s.id,
    s.sha256_hash,
    s.file_name,
    s.status,
    s.verdict,
    s.confidence_score,
    s.submitted_at,
    s.analysis_completed_at,
    COUNT(DISTINCT b.id) as behavior_count,
    COUNT(DISTINCT i.id) as ioc_count,
    MAX(b.severity) as max_severity
FROM samples s
LEFT JOIN behaviors b ON s.id = b.sample_id
LEFT JOIN iocs i ON s.id = i.sample_id
GROUP BY s.id;

-- Active threat indicators view
CREATE VIEW v_active_iocs AS
SELECT
    ioc_type,
    value,
    confidence,
    tlp,
    ti_tags,
    COUNT(DISTINCT sample_id) as sample_count,
    MAX(first_seen) as first_seen,
    MAX(last_seen) as last_seen
FROM iocs
WHERE NOT expired AND tlp != 'red'
GROUP BY ioc_type, value, confidence, tlp, ti_tags;

-- MITRE ATT&CK coverage view
CREATE VIEW v_mitre_attack_coverage AS
SELECT
    mitre_attack_tactic,
    mitre_attack_technique,
    COUNT(DISTINCT sample_id) as detection_count,
    ARRAY_AGG(DISTINCT sigma_rule_name) as detecting_rules
FROM behaviors
WHERE mitre_attack_id IS NOT NULL
GROUP BY mitre_attack_tactic, mitre_attack_technique;

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Default admin user (password: change-me-immediately)
INSERT INTO users (username, email, password_hash, role, permissions) VALUES
('admin', 'admin@localhost', crypt('change-me-immediately', gen_salt('bf')), 'admin',
 '["samples:read", "samples:write", "samples:delete", "analysis:read", "analysis:write",
   "users:read", "users:write", "config:read", "config:write", "audit:read"]'::jsonb);

-- Default sandbox types
INSERT INTO sandboxes (name, sandbox_type, os_type, os_version, architecture, capabilities, status) VALUES
('capev2-windows10-x64', 'capev2', 'windows', '10', 'x86_64',
 '["malware_analysis", "behavioral_monitoring", "memory_dump", "network_capture"]'::jsonb, 'offline'),
('capev2-linux-x64', 'capev2', 'linux', 'ubuntu-22.04', 'x86_64',
 '["malware_analysis", "behavioral_monitoring", "network_capture"]'::jsonb, 'offline'),
('e2b-code-interpreter', 'e2b', 'linux', 'alpine-3.18', 'x86_64',
 '["code_execution", "ephemeral", "network_restricted"]'::jsonb, 'offline'),
('kasm-browser', 'kasm', 'linux', 'ubuntu-22.04', 'x86_64',
 '["browser_isolation", "document_viewing", "network_restricted"]'::jsonb, 'offline');
