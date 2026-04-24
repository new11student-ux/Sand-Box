-- DRAKVUF results storage
CREATE TABLE drakvuf_analysis (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sample_id UUID REFERENCES samples(id),
    job_id TEXT UNIQUE NOT NULL,
    status TEXT CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    memory_artifacts JSONB,  -- Store introspection findings
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- MITRE tagging with versioning
CREATE TABLE mitre_tags (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sample_id UUID REFERENCES samples(id),
    technique_id TEXT NOT NULL,  -- e.g., "T1059.001"
    tactic_id TEXT NOT NULL,     -- e.g., "TA0002"
    confidence FLOAT CHECK (confidence BETWEEN 0 AND 1),
    tagger_version TEXT NOT NULL,  -- Track rule engine version
    evidence_summary JSONB,        -- Why was this tagged?
    analyst_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(sample_id, technique_id, tagger_version)
);

-- Honeypot event correlation
CREATE TABLE honeypot_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cowrie_session_id TEXT,
    attacker_ip INET,
    event_type TEXT,  -- login, command, download, etc.
    raw_event JSONB,
    correlated_sample_id UUID REFERENCES samples(id),  -- If file was downloaded
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_mitre_sample ON mitre_tags(sample_id);
CREATE INDEX idx_mitre_technique ON mitre_tags(technique_id) WHERE confidence > 0.7;
CREATE INDEX idx_honeypot_ip ON honeypot_events(attacker_ip);
